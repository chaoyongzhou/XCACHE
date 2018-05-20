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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "cset.h"

#include "cxml.h"
#include "task.inc"
#include "task.h"
#include "taskcfg.inc"
#include "taskcfg.h"
#include "csocket.h"
#include "cepoll.h"
#include "task.inc"

#include "cmpic.inc"
#include "cmpie.h"
#include "cmisc.h"
#include "crbuff.h"
#include "cbuffer.h"

#include "db_internal.h"
#include "cparacfg.inc"

#include "ccallback.h"

/**
*
* Alexei
* ======
*
* CWND, RTT, PKT LOSS
* 1. task TCPINFO after send 15KB, get CWND: cur_cwnd
* 2. compute nex CWND: next_cwnd = t * last_cwnd + (1 - t) * cur_cwnd, where t is configurable parameter, range in [0,1]
* 3. compute BW: next_cwnd * MTU / RTT
*
**/

static UINT32  g_tmp_encode_size = 0;

static UINT32  g_xmod_node_tmp_encode_size = 0;
static UINT8   g_xmod_node_tmp_encode_buff[ 64 ];

#if 0
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos__;\
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos__ = 0; __pos__ < len; __pos__ ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos__ ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif


STATIC_CAST static const char *csocket_tcpi_stat(const int tcpi_stat)
{
    switch(tcpi_stat)
    {
        case CSOCKET_TCP_ESTABLISHED: return "TCP_ESTABLISHED";
        case CSOCKET_TCP_SYN_SENT   : return "TCP_SYN_SENT";
        case CSOCKET_TCP_SYN_RECV   : return "TCP_SYN_RECV";
        case CSOCKET_TCP_FIN_WAIT1  : return "TCP_FIN_WAIT1";
        case CSOCKET_TCP_FIN_WAIT2  : return "TCP_FIN_WAIT2";
        case CSOCKET_TCP_TIME_WAIT  : return "TCP_TIME_WAIT";
        case CSOCKET_TCP_CLOSE      : return "TCP_CLOSE";
        case CSOCKET_TCP_CLOSE_WAIT : return "TCP_CLOSE_WAIT";
        case CSOCKET_TCP_LAST_ACK   : return "TCP_LAST_ACK";
        case CSOCKET_TCP_LISTEN     : return "TCP_LISTEN";
        case CSOCKET_TCP_CLOSING    : return "TCP_CLOSING";
        default             :
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_tcpi_stat: unknown tcpi_stat = %d\n", tcpi_stat);
    }
    return "unknown state";
}

void csocket_tcpi_stat_print(LOG *log, const int sockfd)
{
    CSOCKET_TCPI info;
    socklen_t info_len;

    info_len = sizeof(CSOCKET_TCPI);
    if(0 != getsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_INFO , (char *)&info, &info_len))
    {
        sys_log(log, "csocket_tcpi_stat_print: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return;
    }

    sys_log(log, "csocket_tcpi_stat_print: sockfd %d tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
    return;
}

STATIC_CAST static EC_BOOL __csocket_cnode_recv_runner(CSOCKET_CNODE *csocket_cnode, CCALLBACK_NODE *ccallback_node)
{
    CSOCKET_CNODE_RECV_CALLBACK    recv_callback;

    recv_callback = (CSOCKET_CNODE_RECV_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return recv_callback(CCALLBACK_NODE_DATA(ccallback_node), csocket_cnode);
}

STATIC_CAST static EC_BOOL __csocket_cnode_send_runner(CSOCKET_CNODE *csocket_cnode, CCALLBACK_NODE *ccallback_node)
{
    CSOCKET_CNODE_SEND_CALLBACK    send_callback;

    send_callback = (CSOCKET_CNODE_SEND_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return send_callback(CCALLBACK_NODE_DATA(ccallback_node), csocket_cnode);
}

STATIC_CAST static EC_BOOL __csocket_cnode_complete_runner(CSOCKET_CNODE *csocket_cnode, CCALLBACK_NODE *ccallback_node)
{
    CSOCKET_CNODE_COMPLETE_CALLBACK    complete_callback;

    complete_callback = (CSOCKET_CNODE_COMPLETE_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return complete_callback(CCALLBACK_NODE_DATA(ccallback_node), csocket_cnode);
}

STATIC_CAST static EC_BOOL __csocket_cnode_close_runner(CSOCKET_CNODE *csocket_cnode, CCALLBACK_NODE *ccallback_node)
{
    CSOCKET_CNODE_CLOSE_CALLBACK    close_callback;

    close_callback = (CSOCKET_CNODE_CLOSE_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return close_callback(CCALLBACK_NODE_DATA(ccallback_node), csocket_cnode);
}

STATIC_CAST static EC_BOOL __csocket_cnode_shutdown_runner(CSOCKET_CNODE *csocket_cnode, CCALLBACK_NODE *ccallback_node)
{
    CSOCKET_CNODE_SHUTDOWN_CALLBACK    shutdown_callback;

    shutdown_callback = (CSOCKET_CNODE_SHUTDOWN_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return shutdown_callback(CCALLBACK_NODE_DATA(ccallback_node), csocket_cnode);
}

STATIC_CAST static EC_BOOL __csocket_cnode_timeout_runner(CSOCKET_CNODE *csocket_cnode, CCALLBACK_NODE *ccallback_node)
{
    CSOCKET_CNODE_TIMEOUT_CALLBACK    timeout_callback;

    timeout_callback = (CSOCKET_CNODE_TIMEOUT_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return timeout_callback(CCALLBACK_NODE_DATA(ccallback_node), csocket_cnode);
}

EC_BOOL csocket_cnode_init(CSOCKET_CNODE *csocket_cnode)
{
    CSOCKET_CNODE_TCID(csocket_cnode   )            = CMPI_ERROR_TCID;
    CSOCKET_CNODE_COMM(csocket_cnode   )            = CMPI_ERROR_COMM;
    CSOCKET_CNODE_SIZE(csocket_cnode   )            = 0              ;
    CSOCKET_CNODE_SOCKFD(csocket_cnode )            = CMPI_ERROR_SOCKFD;

    CSOCKET_CNODE_TYPE(csocket_cnode )              = CSOCKET_TYPE_ERR;
    CSOCKET_CNODE_UNIX(csocket_cnode )              = BIT_FALSE;
    CSOCKET_CNODE_IS_USED(csocket_cnode)            = BIT_FALSE; /*default is not used*/
    CSOCKET_CNODE_READING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_REUSING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_CLOSING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_PENDING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_LOOPING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_NONBLOCK(csocket_cnode)           = BIT_TRUE;

    CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)      = CMPI_ERROR_IPADDR;
    CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)        = CMPI_ERROR_CLNTPORT;

    CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode) = CSOCKET_SEND_ONCE_MAX_SIZE;
    CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode) = CSOCKET_RECV_ONCE_MAX_SIZE;

    CSOCKET_CNODE_STATUS(csocket_cnode)             = CSOCKET_CNODE_NONA_TASKC_NODE;

    CSOCKET_CNODE_IPADDR(csocket_cnode )            = CMPI_ERROR_IPADDR;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)            = CMPI_ERROR_SRVPORT;

    CSOCKET_CNODE_LOAD(csocket_cnode)               = 0;
    CSOCKET_CNODE_PKT_POS(csocket_cnode)            = 0;

    CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode)  = NULL_PTR;
    CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode)  = NULL_PTR;

    ccallback_list_init(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode));
    ccallback_list_set_name(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), (const char *)"CSOCKET_CNODE_RECV_CALLBACK_LIST");
    ccallback_list_set_filter(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), (CCALLBACK_FILTER)NULL_PTR);
    ccallback_list_set_runner(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), (CCALLBACK_RUNNER)__csocket_cnode_recv_runner);

    ccallback_list_init(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode));
    ccallback_list_set_name(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), (const char *)"CSOCKET_CNODE_SEND_CALLBACK_LIST");
    ccallback_list_set_filter(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), (CCALLBACK_FILTER)NULL_PTR);
    ccallback_list_set_runner(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), (CCALLBACK_RUNNER)__csocket_cnode_send_runner);

    ccallback_list_init(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode));
    ccallback_list_set_name(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), (const char *)"CSOCKET_CNODE_COMPLETE_CALLBACK_LIST");
    ccallback_list_set_filter(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), (CCALLBACK_FILTER)NULL_PTR);
    ccallback_list_set_runner(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), (CCALLBACK_RUNNER)__csocket_cnode_complete_runner);

    ccallback_list_init(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode));
    ccallback_list_set_name(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), (const char *)"CSOCKET_CNODE_CLOSE_CALLBACK_LIST");
    ccallback_list_set_filter(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), (CCALLBACK_FILTER)NULL_PTR);
    ccallback_list_set_runner(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), (CCALLBACK_RUNNER)__csocket_cnode_close_runner);

    ccallback_list_init(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode));
    ccallback_list_set_name(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), (const char *)"CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST");
    ccallback_list_set_filter(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), (CCALLBACK_FILTER)NULL_PTR);
    ccallback_list_set_runner(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), (CCALLBACK_RUNNER)__csocket_cnode_shutdown_runner);

    ccallback_list_init(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode));
    ccallback_list_set_name(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), (const char *)"CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST");
    ccallback_list_set_filter(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), (CCALLBACK_FILTER)NULL_PTR);
    ccallback_list_set_runner(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), (CCALLBACK_RUNNER)__csocket_cnode_timeout_runner);

    return (EC_TRUE);
}

EC_BOOL csocket_cnode_clean(CSOCKET_CNODE *csocket_cnode)
{
    ccallback_list_clean(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode));
    ccallback_list_clean(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode));
    ccallback_list_clean(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode));
    ccallback_list_clean(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode));
    ccallback_list_clean(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode));
    ccallback_list_clean(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode));

    ASSERT(NULL_PTR == CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode));
    ASSERT(NULL_PTR == CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode));

    CSOCKET_CNODE_TCID(csocket_cnode   )            = CMPI_ERROR_TCID;
    CSOCKET_CNODE_COMM(csocket_cnode   )            = CMPI_ERROR_COMM;
    CSOCKET_CNODE_SIZE(csocket_cnode   )            = 0              ;

    if(0 < CSOCKET_CNODE_SOCKFD(csocket_cnode ))
    {
        csocket_close(CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_SOCKFD(csocket_cnode )        = CMPI_ERROR_SOCKFD;
    }
    else
    {
        CSOCKET_CNODE_SOCKFD(csocket_cnode )        = CMPI_ERROR_SOCKFD;
    }

    CSOCKET_CNODE_TYPE(csocket_cnode )              = CSOCKET_TYPE_ERR;
    CSOCKET_CNODE_UNIX(csocket_cnode )              = BIT_FALSE;
    CSOCKET_CNODE_IS_USED(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_READING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_REUSING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_CLOSING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_PENDING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_LOOPING(csocket_cnode)            = BIT_FALSE;
    CSOCKET_CNODE_NONBLOCK(csocket_cnode)           = BIT_TRUE;

    CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)      = CMPI_ERROR_IPADDR;
    CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)        = CMPI_ERROR_CLNTPORT;

    CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode) = 0;
    CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode) = 0;

    CSOCKET_CNODE_STATUS(csocket_cnode)             = CSOCKET_CNODE_NONA_TASKC_NODE;

    CSOCKET_CNODE_IPADDR(csocket_cnode )            = CMPI_ERROR_IPADDR;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)            = CMPI_ERROR_SRVPORT;

    CSOCKET_CNODE_LOAD(csocket_cnode)               = 0;
    CSOCKET_CNODE_PKT_POS(csocket_cnode)            = 0;

    return (EC_TRUE);
}

void csocket_cnode_clear(CSOCKET_CNODE *csocket_cnode)
{
    csocket_cnode_callback_when_close(csocket_cnode);

    CSOCKET_CNODE_PKT_POS(csocket_cnode)            = 0;

    return;
}

CSOCKET_CNODE * csocket_cnode_new(const UINT32 location)
{
    CSOCKET_CNODE *csocket_cnode;

    alloc_static_mem(MM_CSOCKET_CNODE, &csocket_cnode, location);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_cnode_new: failed to alloc CSOCKET_CNODE\n");
        return (NULL_PTR);
    }

    csocket_cnode_init(csocket_cnode);

    CSOCKET_CNODE_IS_USED(csocket_cnode) = BIT_TRUE; /*set used*/

    CSOCKET_CNODE_SET_CONNECTED(csocket_cnode);

    return (csocket_cnode);
}

EC_BOOL csocket_cnode_free(CSOCKET_CNODE *csocket_cnode)
{
    if(NULL_PTR != csocket_cnode)
    {
        ASSERT(BIT_TRUE == CSOCKET_CNODE_IS_USED(csocket_cnode));

        csocket_cnode_clean(csocket_cnode);

        free_static_mem(MM_CSOCKET_CNODE, csocket_cnode, LOC_CSOCKET_0001);
    }
    return (EC_TRUE);
}

CCALLBACK_NODE *csocket_cnode_search_recv_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_search(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), name, data, func);
}

CCALLBACK_NODE *csocket_cnode_search_send_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_search(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), name, data, func);
}

CCALLBACK_NODE *csocket_cnode_search_complete_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_search(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), name, data, func);
}

CCALLBACK_NODE *csocket_cnode_search_close_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_search(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), name, data, func);
}

CCALLBACK_NODE *csocket_cnode_search_shutdown_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_search(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), name, data, func);
}

CCALLBACK_NODE *csocket_cnode_search_timeout_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_search(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_push_recv_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT,"[DEBUG] csocket_cnode_push_recv_callback: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    if(NULL_PTR == ccallback_list_push(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), name, data, func))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_push_send_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT,"[DEBUG] csocket_cnode_push_send_callback: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    if(NULL_PTR == ccallback_list_push(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), name, data, func))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_push_complete_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT,"[DEBUG] csocket_cnode_push_complete_callback: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    if(NULL_PTR == ccallback_list_push(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), name, data, func))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_push_close_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT,"[DEBUG] csocket_cnode_push_close_callback: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    if(NULL_PTR == ccallback_list_push(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), name, data, func))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_push_shutdown_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT,"[DEBUG] csocket_cnode_push_shutdown_callback: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    if(NULL_PTR == ccallback_list_push(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), name, data, func))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_push_timeout_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT,"[DEBUG] csocket_cnode_push_timeout_callback: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    if(NULL_PTR == ccallback_list_push(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), name, data, func))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_erase_recv_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_erase(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_erase_send_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_erase(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_erase_complete_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_erase(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_erase_close_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_erase(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_erase_shutdown_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_erase(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_erase_timeout_callback(CSOCKET_CNODE *csocket_cnode, const char *name, const UINT32 data, const UINT32 func)
{
    return ccallback_list_erase(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), name, data, func);
}

EC_BOOL csocket_cnode_reset_recv_callback(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_cnode_reset_recv_callback: sockfd %d reset recv callback list\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return ccallback_list_reset(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode));
}

EC_BOOL csocket_cnode_reset_send_callback(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_cnode_reset_send_callback: sockfd %d reset send callback list\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return ccallback_list_reset(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode));
}

EC_BOOL csocket_cnode_reset_complete_callback(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_cnode_reset_complete_callback: sockfd %d reset complete callback list\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return ccallback_list_reset(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode));
}

EC_BOOL csocket_cnode_reset_close_callback(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_cnode_reset_close_callback: sockfd %d reset close callback list\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return ccallback_list_reset(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode));
}

EC_BOOL csocket_cnode_reset_shutdown_callback(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_cnode_reset_shutdown_callback: sockfd %d reset shutdown callback list\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return ccallback_list_reset(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode));
}

EC_BOOL csocket_cnode_reset_timeout_callback(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_cnode_reset_timeout_callback: sockfd %d reset timeout callback list\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return ccallback_list_reset(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode));
}

EC_BOOL csocket_cnode_callback_when_recv(CSOCKET_CNODE *csocket_cnode)
{
    return ccallback_list_run_and_check(CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode), (UINT32)csocket_cnode);
}

EC_BOOL csocket_cnode_callback_when_send(CSOCKET_CNODE *csocket_cnode)
{
    return ccallback_list_run_and_check(CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode), (UINT32)csocket_cnode);
}

EC_BOOL csocket_cnode_callback_when_complete(CSOCKET_CNODE *csocket_cnode)
{
    return ccallback_list_run_and_check(CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode), (UINT32)csocket_cnode);
}

EC_BOOL csocket_cnode_callback_when_close(CSOCKET_CNODE *csocket_cnode)
{
    return ccallback_list_run_not_check(CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode), (UINT32)csocket_cnode);
}

EC_BOOL csocket_cnode_callback_when_shutdown(CSOCKET_CNODE *csocket_cnode)
{
    return ccallback_list_run_not_check(CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode), (UINT32)csocket_cnode);
}

EC_BOOL csocket_cnode_callback_when_timeout(CSOCKET_CNODE *csocket_cnode)
{
    return ccallback_list_run_not_check(CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode), (UINT32)csocket_cnode);
}

EC_BOOL csocket_cnode_close(CSOCKET_CNODE *csocket_cnode)
{
    ASSERT(NULL_PTR != csocket_cnode);

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_cnode_close: close sockfd %d of csocket_cnode %p\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), csocket_cnode);

    if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
    {
        cepoll_clear_node(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }
    csocket_close(CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_SOCKFD(csocket_cnode) = CMPI_ERROR_SOCKFD;

    csocket_cnode_free(csocket_cnode);
    return (EC_TRUE);
}

CSOCKET_CNODE * csocket_cnode_unix_new(const UINT32 tcid, const int sockfd, const uint32_t type, const UINT32 ipaddr, const UINT32 srvport)
{
    CSOCKET_CNODE *csocket_cnode;

    alloc_static_mem(MM_CSOCKET_CNODE, &csocket_cnode, LOC_CSOCKET_0002);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_cnode_unix_new: failed to alloc CSOCKET_CNODE\n");
        return (NULL_PTR);
    }

    csocket_cnode_init(csocket_cnode);

    CSOCKET_CNODE_TCID(csocket_cnode  ) = tcid           ;
    CSOCKET_CNODE_COMM(csocket_cnode  ) = CMPI_ERROR_COMM;
    CSOCKET_CNODE_SIZE(csocket_cnode  ) = 0              ;
    CSOCKET_CNODE_SOCKFD(csocket_cnode) = sockfd         ;
    CSOCKET_CNODE_TYPE(csocket_cnode )  = type           ;
    CSOCKET_CNODE_UNIX(csocket_cnode )  = BIT_TRUE       ;
    CSOCKET_CNODE_STATUS(csocket_cnode) = CSOCKET_CNODE_NONA_TASKC_NODE;

    CSOCKET_CNODE_IPADDR(csocket_cnode) = ipaddr;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)= srvport;

    CSOCKET_CNODE_LOAD(csocket_cnode)    = 0;
    CSOCKET_CNODE_PKT_POS(csocket_cnode) = 0;

    CSOCKET_CNODE_SET_CONNECTED(csocket_cnode);

    return (csocket_cnode);
}

void csocket_cnode_close_and_clean_event(CSOCKET_CNODE *csocket_cnode)
{
    if(NULL_PTR != csocket_cnode)
    {
        int      sockfd;
        uint32_t nonblock;

        /*csocket_cnode will be clean up, save sockfd at first*/
        sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

        nonblock = CSOCKET_CNODE_NONBLOCK(csocket_cnode);

        if(BIT_TRUE == nonblock)
        {
            cepoll_del_all(task_brd_default_get_cepoll(), sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        }

        csocket_cnode_callback_when_close(csocket_cnode);
        csocket_cnode_close(csocket_cnode);

        if(BIT_TRUE == nonblock)
        {
            cepoll_clear_node(task_brd_default_get_cepoll(), sockfd);
        }
    }
    return;
}

EC_BOOL csocket_cnode_set_disconnected(CSOCKET_CNODE *csocket_cnode)
{
    if(NULL_PTR != csocket_cnode)
    {
        CSOCKET_CNODE_SET_DISCONNECTED(csocket_cnode);
    }

    return (EC_TRUE);
}

EC_BOOL csocket_cnode_cmp(const CSOCKET_CNODE *csocket_cnode_1, const CSOCKET_CNODE *csocket_cnode_2)
{
    if((NULL_PTR == csocket_cnode_1) && (NULL_PTR == csocket_cnode_2))
    {
        return (EC_TRUE);
    }
    if((NULL_PTR == csocket_cnode_1) || (NULL_PTR == csocket_cnode_2))
    {
        return (EC_FALSE);
    }
    if(CSOCKET_CNODE_TCID(csocket_cnode_1) != CSOCKET_CNODE_TCID(csocket_cnode_2))
    {
        return (EC_FALSE);
    }
    if(CSOCKET_CNODE_SOCKFD(csocket_cnode_1) != CSOCKET_CNODE_SOCKFD(csocket_cnode_2))
    {
        return (EC_FALSE);
    }

    /*when comm not set, then skip comparasion*/
    if(CMPI_ERROR_COMM != (CSOCKET_CNODE_COMM(csocket_cnode_1))
    && CMPI_ERROR_COMM != (CSOCKET_CNODE_COMM(csocket_cnode_2))
    && CSOCKET_CNODE_COMM(csocket_cnode_1) != CSOCKET_CNODE_COMM(csocket_cnode_2))
    {
        return (EC_FALSE);
    }

    /*when size not set, then skip comparasion*/
    if(0 != (CSOCKET_CNODE_SIZE(csocket_cnode_1))
    && 0 != (CSOCKET_CNODE_SIZE(csocket_cnode_2))
    && CSOCKET_CNODE_SIZE(csocket_cnode_1) != CSOCKET_CNODE_SIZE(csocket_cnode_2))
    {
        return (EC_FALSE);
    }

    /*when ipaddr not set, then skip comparasion*/
    if(CMPI_ERROR_IPADDR != (CSOCKET_CNODE_IPADDR(csocket_cnode_1))
    && CMPI_ERROR_IPADDR != (CSOCKET_CNODE_IPADDR(csocket_cnode_2))
    && CSOCKET_CNODE_IPADDR(csocket_cnode_1) != CSOCKET_CNODE_IPADDR(csocket_cnode_2))
    {
        return (EC_FALSE);
    }

    /*when srvport not set, then skip comparasion*/
    if(CMPI_ERROR_SRVPORT != (CSOCKET_CNODE_SRVPORT(csocket_cnode_1))
    && CMPI_ERROR_SRVPORT != (CSOCKET_CNODE_SRVPORT(csocket_cnode_2))
    && (CSOCKET_CNODE_SRVPORT(csocket_cnode_1) != CSOCKET_CNODE_SRVPORT(csocket_cnode_2)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_is_nonblock(const CSOCKET_CNODE *csocket_cnode)
{
    if(EC_FALSE == csocket_is_nonblock(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
    {
        //ASSERT(BIT_FALSE == CSOCKET_CNODE_NONBLOCK(csocket_cnode));
        return (EC_FALSE);
    }
    //ASSERT(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode));
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_is_connected(const CSOCKET_CNODE *csocket_cnode)
{
    if(EC_FALSE == csocket_is_connected(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void csocket_cnode_print(LOG *log, const CSOCKET_CNODE *csocket_cnode)
{
    sys_print(log, "csocket_cnode %p: sockfd = %d, srvipaddr = %s, srvport = %ld, tcid = %s, comm = %ld, size = %ld, send_once = %ld, recv_once %ld\n",
                csocket_cnode, CSOCKET_CNODE_SOCKFD(csocket_cnode),
                CSOCKET_CNODE_IPADDR_STR(csocket_cnode),
                CSOCKET_CNODE_SRVPORT(csocket_cnode),
                CSOCKET_CNODE_TCID_STR(csocket_cnode),
                CSOCKET_CNODE_COMM(csocket_cnode),
                CSOCKET_CNODE_SIZE(csocket_cnode),
                CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode),
                CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode)
                );
    return;
}

const char *csocket_cnode_tcpi_stat_desc(const CSOCKET_CNODE *csocket_cnode)
{
    return csocket_tcpi_stat_desc(CSOCKET_CNODE_SOCKFD(csocket_cnode));
}

EC_BOOL csocket_cnode_irecv(CSOCKET_CNODE *csocket_cnode)
{
    return csocket_cnode_callback_when_recv(csocket_cnode);
}

EC_BOOL csocket_cnode_isend(CSOCKET_CNODE *csocket_cnode)
{
    return csocket_cnode_callback_when_send(csocket_cnode);
}

EC_BOOL csocket_cnode_icomplete(CSOCKET_CNODE *csocket_cnode)
{
    ASSERT(NULL_PTR != csocket_cnode);

    csocket_cnode_callback_when_complete(csocket_cnode);

    if(BIT_FALSE == CSOCKET_CNODE_REUSING(csocket_cnode))
    {
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_cnode_icomplete: sockfd %d, resuing: false\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
        csocket_cnode_close(csocket_cnode);
        return (EC_TRUE);
    }

    if(BIT_TRUE  == CSOCKET_CNODE_CLOSING(csocket_cnode))
    {
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_cnode_icomplete: sockfd %d, closing: true\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
        csocket_cnode_close(csocket_cnode);
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL csocket_cnode_ishutdown(CSOCKET_CNODE *csocket_cnode)
{
    ASSERT(NULL_PTR != csocket_cnode);

    csocket_cnode_callback_when_shutdown(csocket_cnode);

    csocket_cnode_close(csocket_cnode);

    return (EC_TRUE);
}

EC_BOOL csocket_cnode_iclose(CSOCKET_CNODE *csocket_cnode)
{
    ASSERT(NULL_PTR != csocket_cnode);

    csocket_cnode_callback_when_close(csocket_cnode);

    if(BIT_FALSE == CSOCKET_CNODE_REUSING(csocket_cnode))
    {
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_cnode_iclose: sockfd %d, resuing: false\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
        csocket_cnode_close(csocket_cnode);
        return (EC_TRUE);
    }

    if(BIT_TRUE  == CSOCKET_CNODE_CLOSING(csocket_cnode))
    {
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_cnode_iclose: sockfd %d, closing: true\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
        csocket_cnode_close(csocket_cnode);
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL csocket_cnode_itimeout(CSOCKET_CNODE *csocket_cnode)
{
    ASSERT(NULL_PTR != csocket_cnode);

    csocket_cnode_callback_when_timeout(csocket_cnode);

    /*do not walk through iclose procedure*/
    if(BIT_FALSE == CSOCKET_CNODE_LOOPING(csocket_cnode))
    {
        csocket_cnode_close(csocket_cnode);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_cnode_send(CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos)
{
    if(CSOCKET_TYPE_TCP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return csocket_write(CSOCKET_CNODE_SOCKFD(csocket_cnode),
                         CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode), out_buff, out_buff_max_len, pos);
    }

    if(CSOCKET_TYPE_UDP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return csocket_udp_write(CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_IPADDR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                             CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode), out_buff, out_buff_max_len, pos);
    }

    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "error:csocket_cnode_send: sockfd %d, invalid type %u \n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_TYPE(csocket_cnode));
    return (EC_FALSE);
}

EC_BOOL csocket_cnode_recv(CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    if(CSOCKET_TYPE_TCP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return csocket_read(CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode), in_buff, in_buff_expect_len, pos);
    }

    if(CSOCKET_TYPE_UDP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return csocket_udp_read(CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_IPADDR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                            CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode), in_buff, in_buff_expect_len, pos);
    }
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "error:csocket_cnode_recv: sockfd %d, invalid type %u \n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_TYPE(csocket_cnode));
    return (EC_FALSE);
}

EC_BOOL csocket_cnode_udp_send(CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos)
{
    return csocket_udp_write(CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_IPADDR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                             CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode), out_buff, out_buff_max_len, pos);
}

EC_BOOL csocket_cnode_udp_recv(CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    return csocket_udp_read(CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_IPADDR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                            CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode), in_buff, in_buff_expect_len, pos);
}

void sockfd_print(LOG *log, const void *data)
{
    sys_print(log, "%d\n", UINT32_TO_INT32((UINT32)data));
    csocket_tcpi_stat_print(log, UINT32_TO_INT32((UINT32)data));
}

EC_BOOL csocket_fd_clean(FD_CSET *sockfd_set)
{
    FD_ZERO(SOCKFD_SET(sockfd_set));
    return (EC_TRUE);
}

EC_BOOL csocket_fd_set(const int sockfd, FD_CSET *sockfd_set, int *max_sockfd)
{
    //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_fd_set: sockfd %d add to FD_CSET %lx\n", sockfd, sockfd_set);
    FD_SET(sockfd, SOCKFD_SET(sockfd_set));
    if((*max_sockfd) < sockfd)
    {
        (*max_sockfd) = sockfd;
    }

    return (EC_TRUE);
}

EC_BOOL csocket_fd_isset(const int sockfd, FD_CSET *sockfd_set)
{
    if(FD_ISSET(sockfd, SOCKFD_SET(sockfd_set)))
    {
        //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_fd_isset: sockfd %d was set in FD_CSET %lx\n", sockfd, sockfd_set);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csocket_fd_clr(const int sockfd, FD_CSET *sockfd_set)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_fd_clr: sockfd %d was cleared in FD_CSET %p\n", sockfd, sockfd_set);
    FD_CLR(sockfd, SOCKFD_SET(sockfd_set));
    return (EC_TRUE);
}

EC_BOOL csocket_fd_clone(FD_CSET *src_sockfd_set, FD_CSET *des_sockfd_set)
{
    //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_fd_clone: clone %lx ---> %lx\n", src_sockfd_set, des_sockfd_set);
    (*SOCKFD_SET(des_sockfd_set)) = (*SOCKFD_SET(src_sockfd_set));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL csocket_srv_addr_init( const UINT32 srv_ipaddr, const UINT32 srv_port, struct sockaddr_in *srv_addr)
{
    srv_addr->sin_family      = AF_INET;
    srv_addr->sin_port        = htons( atoi(c_word_to_port(srv_port)) );
    srv_addr->sin_addr.s_addr = INADDR_ANY/*gdb_hton_uint32((uint32_t)srv_ipaddr)*/;
    bzero(srv_addr->sin_zero, sizeof(srv_addr->sin_zero)/sizeof(srv_addr->sin_zero[0]));

    return  ( EC_TRUE );
}

EC_BOOL csocket_client_addr_init( const UINT32 srv_ipaddr, const UINT32 srv_port, struct sockaddr_in *srv_addr)
{
    struct sockaddr_in     ipv4addr;
    //struct hostent        *phost;

    if ( 0 < inet_pton(AF_INET, c_word_to_ipv4(srv_ipaddr), &(ipv4addr.sin_addr)) )
    {
        /* fill ip addr and port */
        srv_addr->sin_family = AF_INET;
        srv_addr->sin_port   = htons( (uint32_t)srv_port );
        srv_addr->sin_addr   = ipv4addr.sin_addr;
        bzero(srv_addr->sin_zero, sizeof(srv_addr->sin_zero)/sizeof(srv_addr->sin_zero[0]));
        return(EC_TRUE);
    }

#if 0
    /*otherwise, query DNS*/
    phost = gethostbyname(c_word_to_ipv4(srv_ipaddr));
    if (1)
    {
        if(NULL_PTR == phost)
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_client_addr_init: unknown ip: %s\n",
                               c_word_to_ipv4(srv_ipaddr));
            return (EC_FALSE);
        }


        /* fill ip addr and port */
        srv_addr->sin_family = AF_INET;
        srv_addr->sin_port   = htons( (uint32_t)srv_port );
        srv_addr->sin_addr   = *((struct in_addr *)(phost->h_addr));
        bzero(srv_addr->sin_zero, sizeof(srv_addr->sin_zero)/sizeof(srv_addr->sin_zero[0]));
        return (EC_TRUE);
    }
#endif
    dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_client_addr_init: unknown ip: %s\n", c_word_to_ipv4(srv_ipaddr));
    return (EC_FALSE);
}

EC_BOOL csocket_nonblock_enable(int sockfd)
{
    int flag;

    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_nonblock_enable: sockfd %d\n", sockfd);
    flag = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, O_NONBLOCK | flag);
    return (EC_TRUE);
}

EC_BOOL csocket_nonblock_disable(int sockfd)
{
    int flag;

    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_nonblock_disable: sockfd %d\n", sockfd);
    flag = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, (~O_NONBLOCK) & flag);
    return (EC_TRUE);
}

EC_BOOL csocket_is_nonblock(const int sockfd)
{
    int flag;

    flag = fcntl(sockfd, F_GETFL, 0);

    if(flag & O_NONBLOCK)
    {
        //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_nonblock: sockfd %d is nonblock\n", sockfd);
        return (EC_TRUE);
    }
    //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_nonblock: sockfd %d is NOT nonblock\n", sockfd);
    return (EC_FALSE);
}

EC_BOOL csocket_nagle_disable(int sockfd)
{
    int flag;
    flag = 1;
    if( 0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_NODELAY, (char *)&flag, sizeof(flag)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_nagle_disable: sockfd %d failed to disable Nagle Algo\n", sockfd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


EC_BOOL csocket_quick_ack_enable(int sockfd)
{
#ifdef __linux__
    int flag;
    flag = 1;
    if(0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, TCP_QUICKACK, (char *) &flag, sizeof(flag)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_quick_ack_enable: sockfd %d failed to enable QUICKACK\n", sockfd);
        return (EC_FALSE);
    }
#endif/*__linux__*/
    return (EC_TRUE);
}

EC_BOOL csocket_finish_enable(int sockfd)
{
    struct linger linger_disable;
    linger_disable.l_onoff  = 0; /*enable FIN*/
    linger_disable.l_linger = 0; /*ignore*/

    if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_LINGER,(const char*)&linger_disable, sizeof(struct linger)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_finish_enable: sockfd %d failed to disable linger\n", sockfd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_reset_enable(int sockfd)
{
    struct linger linger_disable;
    linger_disable.l_onoff  = 1; /*enable RST*/
    linger_disable.l_linger = 0; /*0: RST at once*/

    if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_LINGER,(const char*)&linger_disable, sizeof(struct linger)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_reset_enable: sockfd %d failed to disable linger\n", sockfd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_set_sendbuf_size(int sockfd, const int size)
{
    int flag;

    flag = size;
    if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDBUF, (char *)&flag, sizeof(flag)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_set_sendbuf_size: sockfd %d failed to set SEND BUFF to %d\n",
                           sockfd, flag);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_set_recvbuf_size(int sockfd, const int size)
{
    int flag;

    flag = size;
    if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVBUF, (char *)&flag, sizeof(flag)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_set_recvbuf_size: sockfd %d failed to set RECV BUFF to %d\n",
                           sockfd, flag);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_enable_keepalive(int sockfd)
{
    EC_BOOL ret;

    int flag;
    int keep_idle;
    int keep_interval;
    int keep_count;

    ret = EC_TRUE;/*initialization*/

    flag = 1;/*1: enable KEEPALIVE, 0: disable KEEPALIVE*/
    keep_idle     = CSOCKET_TCP_KEEPIDLE_NSEC;  /*if no data transmission in 10 seconds, start to check socket*/
    keep_interval = CSOCKET_TCP_KEEPINTVL_NSEC; /*send heartbeat packet in interval 5 seconds*/
    keep_count    = CSOCKET_TCP_KEEPCNT_TIMES;  /*send heartbeat packet up to 3 times, if some heartbeat recv ack, then stop. otherwise, regard socket is disconnected*/
    if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_KEEPALIVE, (char *)&flag, sizeof(flag) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_enable_keepalive: sockfd %d failed to set KEEPALIVE\n", sockfd);
        ret = EC_FALSE;
    }

    if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPIDLE, (char *)&keep_idle, sizeof(keep_idle) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_enable_keepalive: sockfd %d failed to set KEEPIDLE\n", sockfd);
        ret = EC_FALSE;
    }

    if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPINTVL, (char *)&keep_interval, sizeof(keep_interval) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_enable_keepalive: sockfd %d failed to set KEEPINTVL\n", sockfd);
        ret = EC_FALSE;
    }

    if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPCNT, (char *)&keep_count, sizeof(keep_count) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_enable_keepalive: sockfd %d failed to set KEEPCNT\n", sockfd);
        ret = EC_FALSE;
    }

    return (ret);
}

EC_BOOL csocket_disable_keepalive(int sockfd)
{
    EC_BOOL ret;

    int flag;

    ret = EC_TRUE;/*initialization*/

    flag = 0;/*1: enable KEEPALIVE, 0: disable KEEPALIVE*/
    if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_KEEPALIVE, (char *)&flag, sizeof(flag) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_disable_keepalive: sockfd %d failed to disable KEEPALIVE\n", sockfd);
        ret = EC_FALSE;
    }

    return (ret);
}

EC_BOOL csocket_optimize(int sockfd, const UINT32 csocket_block_mode)
{
    EC_BOOL ret;

    ret = EC_TRUE;
    /* optimization 1: disalbe Nagle Algorithm */
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_NODELAY, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to disable Nagle Algo\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /*optimization: quick ack*/
#ifdef __linux__
    if(1)
    {
        int flag;
        flag = 1;
        if(0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, TCP_QUICKACK, (char *) &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_optimize: sockfd %d failed to enable QUICKACK\n", sockfd);
            ret = EC_FALSE;
        }
    }
#endif/*__linux__*/

    /* optimization 2.1: when flag > 0, set SEND_BUFF size per packet - Flow Control*/
    /* optimization 2.2: when flag = 0, the data buff to send will NOT copy to system buff but send out directly*/
    if(1)
    {
        int flag;
        flag = CSOCKET_SO_SNDBUFF_SIZE;
        if(0 <= flag && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDBUF, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set SEND BUFF to %d\n", sockfd, flag);
            ret = EC_FALSE;
        }
    }

    /* optimization 3.1: when flag > 0, set RECV_BUFF size per packet - Flow Control*/
    /* optimization 3.2: when flag = 0, the data buff to recv will NOT copy from system buff but recv in directly*/
    if(1)
    {
        int flag;
        flag = CSOCKET_SO_RCVBUFF_SIZE;
        if(0 <= flag && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVBUF, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set RECV BUFF to %d\n", sockfd, flag);
            ret = EC_FALSE;
        }
    }

    /* optimization 4: set KEEPALIVE*/
    /*note: CSOCKET_SO_KEEPALIVE is only for TCP protocol but not for UDP, hence some guys need to implement heartbeat mechanism */
    /*in application level to cover both TCP and UDP*/
    if(SWITCH_ON == CSOCKET_SO_KEEPALIVE_SWITCH)
    {
        int flag;
        int keep_idle;
        int keep_interval;
        int keep_count;

        flag = 1;/*1: enable KEEPALIVE, 0: disable KEEPALIVE*/
        keep_idle     = CSOCKET_TCP_KEEPIDLE_NSEC; /*if no data transmission in 10 seconds, start to check socket*/
        keep_interval = CSOCKET_TCP_KEEPINTVL_NSEC;  /*send heartbeat packet in interval 5 seconds*/
        keep_count    = CSOCKET_TCP_KEEPCNT_TIMES;  /*send heartbeat packet up to 3 times, if some heartbeat recv ack, then stop. otherwise, regard socket is disconnected*/
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_KEEPALIVE, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set KEEPALIVE\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPIDLE, (char *)&keep_idle, sizeof(keep_idle) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set KEEPIDLE\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPINTVL, (char *)&keep_interval, sizeof(keep_interval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set KEEPINTVL\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPCNT, (char *)&keep_count, sizeof(keep_count) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set KEEPCNT\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set REUSEADDR\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /* optimization 6: set SEND TIMEOUT. NOTE: the timeout not working for socket connect op*/
    if(0)
    {
        struct timeval timeout;
        time_t usecs = CSOCKET_SO_SNDTIMEO_NSEC * 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_optimize: sockfd %d failed to set SEND TIMEOUT to %d usecs\n",
                                sockfd, (uint32_t)usecs);
            ret = EC_FALSE;
        }
    }

    /* optimization 7: set RECV TIMEOUT. NOTE: the timeout not working for socket connect op*/
    if(0)
    {
        struct timeval timeout;
        time_t usecs = CSOCKET_SO_RCVTIMEO_NSEC * 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_optimize: sockfd %d failed to set RECV TIMEOUT to %d usecs\n",
                                sockfd, (uint32_t)usecs);
            ret = EC_FALSE;
        }
    }

    /* optimization 8: set NONBLOCK*/
    if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode)
    {
        int flag;

        flag = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, O_NONBLOCK | flag);
    }
    else
    {
        int flag;

        flag = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, (~O_NONBLOCK) & flag);
    }

    /*optimization 9: disable linger, i.e., send close socket, stop sending/recving at once*/
    if(1)
    {
        struct linger linger_disable;
        linger_disable.l_onoff  = 0; /*disable*/
        linger_disable.l_linger = 0; /*stop after 0 second, i.e., stop at once*/

        if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_LINGER, (const char*)&linger_disable, sizeof(struct linger)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_optimize: sockfd %d failed to disable linger\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /*optimization 10: sets the minimum number of bytes to process for socket input operations. The default value for CSOCKET_SO_RCVLOWAT is 1*/
    if(0)
    {
        int  recv_lowat_size;

        recv_lowat_size = CSOCKET_SO_RCVLOWAT_SIZE;
        if(0 < recv_lowat_size && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVLOWAT, (const char *) &recv_lowat_size, sizeof(int)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_optimize: sockfd %d failed to set CSOCKET_SO_RCVLOWAT to %d\n", sockfd, recv_lowat_size);
            ret = EC_FALSE;
        }
    }

    /*optimization 11: Sets the minimum number of bytes to process for socket output operations*/
    if(0)
    {
        int  send_lowat_size;

        send_lowat_size = CSOCKET_SO_SNDLOWAT_SIZE;
        if(0 < send_lowat_size && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDLOWAT, (const char *) &send_lowat_size, sizeof(int)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_optimize: sockfd %d failed to set CSOCKET_SO_SNDLOWAT to %d\n", sockfd, send_lowat_size);
            ret = EC_FALSE;
        }
    }

    return (ret);
}

EC_BOOL csocket_udp_optimize(int sockfd)
{
    EC_BOOL ret;

    ret = EC_TRUE;
    /* optimization 1: disalbe Nagle Algorithm */
    if(0)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_NODELAY, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to disable Nagle Algo\n", sockfd);
            ret = EC_FALSE;
        }
    }

#ifdef __linux__
    /*optimization: quick ack*/
    if(0)
    {
        int flag;
        flag = 1;
        if(0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, TCP_QUICKACK, (char *) &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_udp_optimize: sockfd %d failed to enable QUICKACK\n", sockfd);
            ret = EC_FALSE;
        }
    }
#endif/*__linux__*/
    /* optimization 2.1: when flag > 0, set SEND_BUFF size per packet - Flow Control*/
    /* optimization 2.2: when flag = 0, the data buff to send will NOT copy to system buff but send out directly*/
    if(1)
    {
        int flag;
        flag = CSOCKET_SO_SNDBUFF_SIZE;
        if(0 <= flag && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDBUF, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set SEND BUFF to %d\n", sockfd, flag);
            ret = EC_FALSE;
        }
    }

    /* optimization 3.1: when flag > 0, set RECV_BUFF size per packet - Flow Control*/
    /* optimization 3.2: when flag = 0, the data buff to recv will NOT copy from system buff but recv in directly*/
    if(1)
    {
        int flag;
        flag = CSOCKET_SO_RCVBUFF_SIZE;
        if(0 <= flag && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVBUF, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set RECV BUFF to %d\n", sockfd, flag);
            ret = EC_FALSE;
        }
    }

    /* optimization 4: set KEEPALIVE*/
    /*note: CSOCKET_SO_KEEPALIVE is only for TCP protocol but not for UDP, hence some guys need to implement heartbeat mechanism */
    /*in application level to cover both TCP and UDP*/
    if(0)
    {
        int flag;
        int keep_idle;
        int keep_interval;
        int keep_count;

        flag = 1;/*1: enable KEEPALIVE, 0: disable KEEPALIVE*/
        keep_idle     = CSOCKET_TCP_KEEPIDLE_NSEC; /*if no data transmission in 10 seconds, start to check socket*/
        keep_interval = CSOCKET_TCP_KEEPINTVL_NSEC;  /*send heartbeat packet in interval 5 seconds*/
        keep_count    = CSOCKET_TCP_KEEPCNT_TIMES;  /*send heartbeat packet up to 3 times, if some heartbeat recv ack, then stop. otherwise, regard socket is disconnected*/
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_KEEPALIVE, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set KEEPALIVE\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPIDLE, (char *)&keep_idle, sizeof(keep_idle) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set KEEPIDLE\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPINTVL, (char *)&keep_interval, sizeof(keep_interval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set KEEPINTVL\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPCNT, (char *)&keep_count, sizeof(keep_count) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set KEEPCNT\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set REUSEADDR\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /* optimization 6: set SEND TIMEOUT. NOTE: the timeout not working for socket connect op*/
    if(0)
    {
        struct timeval timeout;
        time_t usecs = CSOCKET_SO_SNDTIMEO_NSEC * 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_optimize: sockfd %d failed to set SEND TIMEOUT to %d usecs\n",
                                sockfd, (uint32_t)usecs);
            ret = EC_FALSE;
        }
    }

    /* optimization 7: set RECV TIMEOUT. NOTE: the timeout not working for socket connect op*/
    if(0)
    {
        struct timeval timeout;
        time_t usecs = CSOCKET_SO_RCVTIMEO_NSEC * 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_udp_optimize: sockfd %d failed to set RECV TIMEOUT to %d usecs\n",
                                sockfd, (uint32_t)usecs);
            ret = EC_FALSE;
        }
    }

    /* optimization 8: set NONBLOCK*/
    if(1)
    {
        int flag;

        flag = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, O_NONBLOCK | flag);
    }

    /*optimization 9: disable linger, i.e., send close socket, stop sending/recving at once*/
    if(1)
    {
        struct linger linger_disable;
        linger_disable.l_onoff  = 0; /*disable*/
        linger_disable.l_linger = 0; /*stop after 0 second, i.e., stop at once*/

        if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_LINGER, (const char*)&linger_disable, sizeof(struct linger)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_udp_optimize: sockfd %d failed to disable linger\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /*optimization 10: sets the minimum number of bytes to process for socket input operations. The default value for CSOCKET_SO_RCVLOWAT is 1*/
    if(0)
    {
        int  recv_lowat_size;

        recv_lowat_size = CSOCKET_SO_RCVLOWAT_SIZE;
        if(0 < recv_lowat_size && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVLOWAT, (const char *) &recv_lowat_size, sizeof(int)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_udp_optimize: sockfd %d failed to set CSOCKET_SO_RCVLOWAT to %d\n", sockfd, recv_lowat_size);
            ret = EC_FALSE;
        }
    }

    /*optimization 11: Sets the minimum number of bytes to process for socket output operations*/
    if(0)
    {
        int  send_lowat_size;

        send_lowat_size = CSOCKET_SO_SNDLOWAT_SIZE;
        if(0 < send_lowat_size && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDLOWAT, (const char *) &send_lowat_size, sizeof(int)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_udp_optimize: sockfd %d failed to set CSOCKET_SO_SNDLOWAT to %d\n", sockfd, send_lowat_size);
            ret = EC_FALSE;
        }
    }

    return (ret);
}

EC_BOOL csocket_listen( const UINT32 srv_ipaddr, const UINT32 srv_port, int *srv_sockfd )
{
    struct sockaddr_in srv_addr;
    int sockfd;

    /* create socket */
    sockfd = csocket_open( AF_INET, SOCK_STREAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_listen: tcp socket failed, errno = %d, errstr = %s\n", errno, strerror(errno));
        return ( EC_FALSE );
    }

    /* init socket addr structer */
    csocket_srv_addr_init( srv_ipaddr, srv_port, &srv_addr);

    /* note: optimization must before listen at server side*/
    if(EC_FALSE == csocket_optimize(sockfd, CSOCKET_IS_NONBLOCK_MODE))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_listen: sockfd %d failed in some optimization\n", sockfd);
    }

    //csocket_nonblock_disable(sockfd);

    if ( 0 !=  bind( sockfd, (struct sockaddr *)&srv_addr, sizeof( srv_addr ) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_listen: bind %s:%ld failed, errno = %d, errstr = %s\n",
                    c_word_to_ipv4(srv_ipaddr), srv_port, errno, strerror(errno));
        close(sockfd);
        return ( EC_FALSE );
    }

    dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "[DEBUG] csocket_listen: bind %s:%ld done\n",
                c_word_to_ipv4(srv_ipaddr), srv_port);

    /* create listen queues */
    if( 0 !=  listen( sockfd, CSOCKET_BACKLOG) )/*SOMAXCONN = 128 is a system constant*/
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_listen: listen failed, errno = %d, errstr = %s\n", errno, strerror(errno));
        close(sockfd);
        return ( EC_FALSE );
    }

    *srv_sockfd = sockfd;

    return ( EC_TRUE );
}

EC_BOOL csocket_accept(const int srv_sockfd, int *conn_sockfd, const UINT32 csocket_block_mode, UINT32 *client_ipaddr, UINT32 *client_port)
{
    int new_sockfd;

    struct sockaddr_in sockaddr_in;
    socklen_t sockaddr_len;

    sockaddr_len = sizeof(struct sockaddr_in);
    new_sockfd = accept(srv_sockfd, (struct sockaddr *)&(sockaddr_in), &(sockaddr_len));
    if( 0 > new_sockfd)
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == csocket_optimize(new_sockfd, csocket_block_mode))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_accept: optimize sockfd %d failed\n", new_sockfd);
    }

    if(CSOCKET_IS_BLOCK_MODE == csocket_block_mode)
    {
        csocket_nonblock_disable(new_sockfd);
    }

    (*client_ipaddr) = c_ipv4_to_word((char *)c_inet_ntos(&(sockaddr_in.sin_addr)));
    (*client_port)   = c_inet_ntohs(sockaddr_in.sin_port);
    (*conn_sockfd)   = new_sockfd;

    return (EC_TRUE);
}

EC_BOOL csocket_get_peer_port(const int sockfd, UINT32 *peer_port)
{
    struct sockaddr_storage sa;
    socklen_t               namelen;

    namelen = sizeof(sa);
    getpeername(sockfd, (struct sockaddr *) &sa, &namelen);

    if(AF_INET == sa.ss_family)
    {
        struct sockaddr_in     *sin;

        sin = (struct sockaddr_in *)&sa;
        (*peer_port) = ntohs(sin->sin_port);
        return (EC_TRUE);
    }

    if(AF_INET6 == sa.ss_family)
    {
        struct sockaddr_in6    *sin6;
        sin6 = (struct sockaddr_in6 *)&sa;
        (*peer_port) = ntohs(sin6->sin6_port);
        return (EC_TRUE);
    }

    (*peer_port) = 0;
    return (EC_TRUE);
}

EC_BOOL csocket_udp_create( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd )
{
    struct sockaddr_in srv_addr;

    int sockfd;

    /* initialize the ip addr and port of server */
    if( EC_FALSE == csocket_client_addr_init( srv_ipaddr, srv_port, &srv_addr ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_udp_create: csocket_client_addr_init failed\n");
        return ( EC_FALSE );
    }

    /* create socket */
    sockfd = csocket_open( AF_INET, SOCK_DGRAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_create: socket error\n");
        return ( EC_FALSE );
    }

    /* note: optimization must before connect at server side*/
    if(EC_FALSE == csocket_udp_optimize(sockfd))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_udp_create: sockfd %d failed in some optimization\n", sockfd);
    }

    *client_sockfd = sockfd;
    return ( EC_TRUE );
}

EC_BOOL csocket_start_udp_bcast_sender( const UINT32 bcast_fr_ipaddr, const UINT32 bcast_port, int *srv_sockfd )
{
    int sockfd;

    sockfd = csocket_open( AF_INET, SOCK_DGRAM, 0/*IPPROTO_UDP*//*only recv the port-matched udp pkt*/  );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_sender: udp socket failed, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
        return ( EC_FALSE );
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_start_udp_bcast_sender: sockfd %d failed to set REUSEADDR, errno = %d, errstr = %s\n",
                                sockfd, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        int flag;
        flag = 1;
        if(0 > setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_BROADCAST, &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_sender: set broadcast flag %d failed, errno = %d, errstr = %s\n",
                                flag, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        struct timeval timeout;
        time_t usecs = 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_start_udp_bcast_sender: sockfd %d failed to set RECV TIMEOUT to %d usecs, errno = %d, errstr = %s\n",
                                sockfd, (uint32_t)usecs, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }
#if 1
    if(1)
    {
        struct sockaddr_in bcast_addr;
        BSET(&bcast_addr, 0, sizeof(bcast_addr));
        bcast_addr.sin_family      = AF_INET;
        //bcast_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);/*send ok*/
        bcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_fr_ipaddr));
        bcast_addr.sin_port        = htons( atoi(c_word_to_port(bcast_port)) );

        if ( 0 !=  bind( sockfd, (struct sockaddr *)&bcast_addr, sizeof( bcast_addr ) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_sender: bind to %s:%ld failed, errno = %d, errstr = %s\n",
                                c_word_to_ipv4(bcast_fr_ipaddr), bcast_port, errno, strerror(errno));
            close(sockfd);
            return ( EC_FALSE );
        }
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "[DEBUG] csocket_start_udp_bcast_sender: bind to %s:%ld successfully\n",
                            c_word_to_ipv4(bcast_fr_ipaddr), bcast_port);
    }
#endif
    *srv_sockfd = sockfd;

    return (EC_TRUE);
}

EC_BOOL csocket_stop_udp_bcast_sender( const int sockfd )
{
    if(CMPI_ERROR_SOCKFD != sockfd)
    {
        close(sockfd);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_start_udp_bcast_recver( const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, int *srv_sockfd )
{
    int sockfd;

    sockfd = csocket_open( AF_INET, SOCK_DGRAM, 0/*IPPROTO_UDP*//*only recv the port-matched udp pkt*/ );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: udp socket failed, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
        return ( EC_FALSE );
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_start_udp_bcast_recver: sockfd %d failed to set REUSEADDR, errno = %d, errstr = %s\n",
                                sockfd, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        int flag;
        flag = 1;
        if(0 > setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_BROADCAST, &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: set broadcast flag %d failed, errno = %d, errstr = %s\n",
                                flag, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        struct timeval timeout;
        time_t usecs = 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_start_udp_bcast_recver: sockfd %d failed to set RECV TIMEOUT to %d usecs, errno = %d, errstr = %s\n",
                              sockfd, (uint32_t)usecs, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }
#if 1
    if(1)
    {
        struct sockaddr_in bcast_addr;
        BSET(&bcast_addr, 0, sizeof(bcast_addr));
        bcast_addr.sin_family      = AF_INET;
        //bcast_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);
        //bcast_addr.sin_addr.s_addr = INADDR_ANY;/*ok,note: if not bind it, socket will recv nothing. faint!*/
        bcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_to_ipaddr));
        bcast_addr.sin_port        = htons( atoi(c_word_to_port(bcast_port)) );

        if ( 0 !=  bind( sockfd, (struct sockaddr *)&bcast_addr, sizeof( bcast_addr ) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: bind to %s:%ld failed, errno = %d, errstr = %s\n",
                                c_word_to_ipv4(bcast_to_ipaddr), bcast_port, errno, strerror(errno));
            close(sockfd);
            return ( EC_FALSE );
        }
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_start_udp_bcast_recver: bind to %s:%ld successfully\n",
                            c_word_to_ipv4(bcast_to_ipaddr), bcast_port);

    }
#endif

    *srv_sockfd = sockfd;

    return (EC_TRUE);
}

EC_BOOL csocket_start_udp_bcast_recver1( const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, int *srv_sockfd )
{
    int sockfd;
    const char *net_if = "eth0";

    sockfd = csocket_open( PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: udp socket failed, errno = %d, errstr = %s\n",
                           errno, strerror(errno));
        return ( EC_FALSE );
    }
    if(1)
    {
        struct ifreq ifr;

        strncpy(ifr.ifr_name, net_if, strlen(net_if) + 1);
        if((ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: get %s flags failed, errno = %d, errstr = %s\n",
                                net_if, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }

        ifr.ifr_flags |= IFF_PROMISC;

        if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1 )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: set %s flags with IFF_PROMISC failed, errno = %d, errstr = %s\n",
                                net_if, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
   }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_start_udp_bcast_recver: sockfd %d failed to set REUSEADDR, errno = %d, errstr = %s\n",
                                sockfd, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        int flag;
        flag = 1;
        if(0 > setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_BROADCAST, &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: set broadcast flag %d failed, errno = %d, errstr = %s\n",
                                flag, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        struct timeval timeout;
        time_t usecs = 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_start_udp_bcast_recver: sockfd %d failed to set RECV TIMEOUT to %d usecs, errno = %d, errstr = %s\n",
                            sockfd, (uint32_t)usecs, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }
#if 1
    if(1)
    {
        struct sockaddr_in bcast_addr;
        BSET(&bcast_addr, 0, sizeof(bcast_addr));
        bcast_addr.sin_family      = AF_INET;
        //bcast_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);
        //bcast_addr.sin_addr.s_addr = INADDR_ANY;/*note: if not bind it, socket will recv nothing. faint!*/
        bcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_to_ipaddr));
        bcast_addr.sin_port        = htons( atoi(c_word_to_port(bcast_port)) );

        if ( 0 !=  bind( sockfd, (struct sockaddr *)&bcast_addr, sizeof( bcast_addr ) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_recver: bind to %s:%ld failed, errno = %d, errstr = %s\n",
                               c_word_to_ipv4(bcast_to_ipaddr), bcast_port, errno, strerror(errno));
            close(sockfd);
            return ( EC_FALSE );
        }
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_start_udp_bcast_recver: bind to %s:%ld failed \n",
                           c_word_to_ipv4(bcast_to_ipaddr), bcast_port);
    }
#endif

    *srv_sockfd = sockfd;

    return (EC_TRUE);
}

EC_BOOL csocket_stop_udp_bcast_recver( const int sockfd )
{
    if(CMPI_ERROR_SOCKFD != sockfd)
    {
        close(sockfd);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_set_promisc(const char *nif, int sock)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, nif,strlen(nif)+1);
    if(-1 == ioctl(sock, SIOCGIFFLAGS, &ifr))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_set_promisc: get %s flags failed, errno = %d, errstr = %s\n",
                            nif, errno, strerror(errno));
        return (EC_FALSE);
    }

   ifr.ifr_flags |= IFF_PROMISC;

   if(-1 == ioctl(sock, SIOCSIFFLAGS, &ifr))
   {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_set_promisc: set %s IFF_PROMISC failed, errno = %d, errstr = %s\n",
                            nif, errno, strerror(errno));
        return (EC_FALSE);
    }

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG]csocket_set_promisc: set %s IFF_PROMISC successfully\n",
                        nif);

    return (EC_TRUE);
}

EC_BOOL csocket_udp_bcast_send(const UINT32 bcast_fr_ipaddr, const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, const UINT8 *data, const UINT32 dlen)
{
    int sockfd;

    sockfd = csocket_open( AF_INET, SOCK_DGRAM, 0/*IPPROTO_UDP*//*only recv the port-matched udp pkt*/  );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_send: udp socket failed, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
        return ( EC_FALSE );
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_start_udp_bcast_send: sockfd %d failed to set REUSEADDR, errno = %d, errstr = %s\n",
                                sockfd, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        int flag;
        flag = 1;
        if(0 > setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_BROADCAST, &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_send: set broadcast flag %d failed, errno = %d, errstr = %s\n",
                                flag, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        struct timeval timeout;
        time_t usecs = 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_start_udp_bcast_send: sockfd %d failed to set RECV TIMEOUT to %d usecs, errno = %d, errstr = %s\n",
                                sockfd, (uint32_t)usecs, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    csocket_set_promisc((char *)"eth0", sockfd);
#if 0
    if(1)
    {
        struct sockaddr_in bcast_addr;
        BSET(&bcast_addr, 0, sizeof(bcast_addr));
        bcast_addr.sin_family      = AF_INET;
        //bcast_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);/*send ok*/
        bcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_fr_ipaddr));
        bcast_addr.sin_port        = htons( atoi(c_word_to_port(bcast_port)) );

        if ( 0 !=  bind( sockfd, (struct sockaddr *)&bcast_addr, sizeof( bcast_addr ) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_bcast_send: bind to %s:%ld failed, errno = %d, errstr = %s\n",
                                c_word_to_ipv4(bcast_fr_ipaddr), bcast_port, errno, strerror(errno));
            close(sockfd);
            return ( EC_FALSE );
        }
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "[DEBUG] csocket_start_udp_bcast_send: bind to %s:%ld successfully\n",
                            c_word_to_ipv4(bcast_fr_ipaddr), bcast_port);
    }
#endif

    csocket_udp_bcast_sendto(sockfd, bcast_to_ipaddr, bcast_port, data, dlen);
    close(sockfd);
    return (EC_TRUE);
}

EC_BOOL csocket_udp_bcast_sendto(const int sockfd, const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, const UINT8 *data, const UINT32 dlen)
{
    struct sockaddr_in bcast_to_addr;

    /*make sure dlen < 255*/
    if(dlen != (dlen & 0xFF))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_udp_bcast_sendto: dlen %ld overflow\n", dlen);
        return (EC_FALSE);
    }

    BSET(&bcast_to_addr, 0, sizeof(bcast_to_addr));
    bcast_to_addr.sin_family = AF_INET;
    //bcast_to_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);
    bcast_to_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_to_ipaddr))/*inet_addr(bcast_to_ipaddr_str)*/;
    bcast_to_addr.sin_port = htons( atoi(c_word_to_port(bcast_port)) );

    if(0 > sendto(sockfd, data, dlen, 0, (struct sockaddr*)&bcast_to_addr,sizeof(bcast_to_addr)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_bcast_sendto: send %ld bytes to bcast %s:%ld failed, errno = %d, errstr = %s\n",
                            dlen, c_word_to_ipv4(bcast_to_ipaddr), bcast_port, errno, strerror(errno));
        return (EC_FALSE);
    }

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_bcast_sendto: send %ld bytes to bcast %s:%ld\n",
                        dlen, c_word_to_ipv4(bcast_to_ipaddr), bcast_port);

    return (EC_TRUE);
}

EC_BOOL csocket_udp_bcast_recvfrom(const int sockfd, const UINT32 bcast_fr_ipaddr, const UINT32 bcast_port, UINT8 *data, const UINT32 max_dlen, UINT32 *dlen)
{
    struct sockaddr_in bcast_fr_addr;
    socklen_t bcast_fr_addr_len;
    int csize;

    BSET(&bcast_fr_addr, 0, sizeof(bcast_fr_addr));
    bcast_fr_addr.sin_family = AF_INET;
    //bcast_fr_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);
    bcast_fr_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_fr_ipaddr))/*inet_addr(bcast_fr_ipaddr_str)*/;
    bcast_fr_addr.sin_port = htons( atoi(c_word_to_port(bcast_port)) );

    bcast_fr_addr_len = sizeof(bcast_fr_addr);

    csize = recvfrom(sockfd, (void *)data, max_dlen, 0, (struct sockaddr *)&bcast_fr_addr, &bcast_fr_addr_len);
    if(0 > csize)
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_bcast_recvfrom: recv from bcast %s:%ld failed, errno = %d, errstr = %s\n",
                            c_word_to_ipv4(bcast_fr_ipaddr), bcast_port, errno, strerror(errno));
        return (EC_FALSE);
    }

    (*dlen) = csize;

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_bcast_recvfrom: recv %d bytes from bcast %s:%ld\n",
                        csize, c_word_to_ipv4(bcast_fr_ipaddr), bcast_port);
    return (EC_TRUE);
}

EC_BOOL csocket_udp_bcast_recvfrom1(const int sockfd, const UINT32 bcast_fr_ipaddr, const UINT32 bcast_port, UINT8 *data, const UINT32 max_dlen, UINT32 *dlen)
{
    struct sockaddr_in bcast_fr_addr;
    socklen_t bcast_fr_addr_len;
    int csize;

    BSET(&bcast_fr_addr, 0, sizeof(bcast_fr_addr));
#if 0
    bcast_fr_addr.sin_family = AF_INET;
    bcast_fr_addr.sin_addr.s_addr = htonl(/*INADDR_ANY*/INADDR_BROADCAST);
    //bcast_fr_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(bcast_ipaddr))/*inet_addr(bcast_ipaddr_str)*/;
    bcast_fr_addr.sin_port = htons( atoi(c_word_to_port(bcast_port)) );
#endif
    bcast_fr_addr_len = sizeof(bcast_fr_addr);

    csize = recvfrom(sockfd, (void *)data, max_dlen, 0, (struct sockaddr *)&bcast_fr_addr, &bcast_fr_addr_len);
    if(0 > csize)
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_bcast_recvfrom: recv from bcast %s:%ld failed, errno = %d, errstr = %s\n",
                            c_word_to_ipv4(bcast_fr_ipaddr), bcast_port, errno, strerror(errno));
        return (EC_FALSE);
    }

    (*dlen) = csize;

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_bcast_recvfrom: recv %d bytes from bcast %s:%ld\n",
                        csize, c_word_to_ipv4(bcast_fr_ipaddr), bcast_port);
    return (EC_TRUE);
}

EC_BOOL csocket_start_udp_mcast_sender( const UINT32 mcast_ipaddr, const UINT32 srv_port, int *srv_sockfd )
{
    int sockfd;

    sockfd = csocket_open( AF_INET, SOCK_DGRAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_mcast_sender: udp socket failed\n");
        return ( EC_FALSE );
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_start_udp_mcast_sender: sockfd %d failed to set REUSEADDR, errno = %d, errstr = %s\n",
                                sockfd, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        int flag;
        flag = 1;
        if(0 > setsockopt(sockfd, CSOCKET_IPPROTO_IP, CSOCKET_IP_MULTICAST_LOOP, &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_mcast_sender: set multicast loop flag %d failed, errno = %d, errstr = %s\n",
                                flag, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    *srv_sockfd = sockfd;

    return (EC_TRUE);
}

EC_BOOL csocket_stop_udp_mcast_sender( const int sockfd, const UINT32 mcast_ipaddr )
{
    if(CMPI_ERROR_SOCKFD != sockfd)
    {
        close(sockfd);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_start_udp_mcast_recver( const UINT32 mcast_ipaddr, const UINT32 srv_port, int *srv_sockfd )
{
    struct sockaddr_in srv_addr;
    int sockfd;

    sockfd = csocket_open( AF_INET, SOCK_DGRAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_mcast_recver: udp socket failed\n");
        return ( EC_FALSE );
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_start_udp_mcast_recver: sockfd %d failed to set REUSEADDR, errno = %d, errstr = %s\n",
                                sockfd, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    if(1)
    {
        int flag;
        flag = 1;
        if(0 > setsockopt(sockfd, CSOCKET_IPPROTO_IP, CSOCKET_IP_MULTICAST_LOOP, &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_mcast_recver: set multicast loop flag %d failed, errno = %d, errstr = %s\n",
                                flag, errno, strerror(errno));
            close(sockfd);
            return (EC_FALSE);
        }
    }

    /*join multicast*/
    if(EC_FALSE == csocket_join_mcast(sockfd, mcast_ipaddr))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_mcast_recver: join mcast %s failed\n", c_word_to_ipv4(mcast_ipaddr));
        close(sockfd);
        return (EC_FALSE);
    }

    /* init socket addr structer */
    csocket_srv_addr_init( mcast_ipaddr/*xxx*/, srv_port, &srv_addr);

    /*udp receiver must bind mcast ipaddr & port*/
    if ( 0 !=  bind( sockfd, (struct sockaddr *)&srv_addr, sizeof( srv_addr ) ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_start_udp_mcast_recver: bind failed, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
        close(sockfd);
        return ( EC_FALSE );
    }

    *srv_sockfd = sockfd;

    return (EC_TRUE);
}

EC_BOOL csocket_stop_udp_mcast_recver( const int sockfd, const UINT32 mcast_ipaddr )
{
    if(EC_FALSE == csocket_drop_mcast(sockfd, mcast_ipaddr))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_stop_udp_mcast_recver: drop mcast %s failed\n", c_word_to_ipv4(mcast_ipaddr));
        close(sockfd);
        return (EC_FALSE);
    }

    close(sockfd);
    return (EC_TRUE);
}

EC_BOOL csocket_join_mcast(const int sockfd, const UINT32 mcast_ipaddr)
{
    struct ip_mreq mreq;

    mreq.imr_multiaddr.s_addr = htonl(UINT32_TO_INT32(mcast_ipaddr));
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if(0 > setsockopt(sockfd, CSOCKET_IPPROTO_IP, CSOCKET_IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_join_mcast: add to mcast %s failed, errno = %d, errstr = %s\n",
                            c_word_to_ipv4(mcast_ipaddr), errno, strerror(errno));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csocket_drop_mcast(const int sockfd, const UINT32 mcast_ipaddr)
{
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = htonl(UINT32_TO_INT32(mcast_ipaddr));
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if(0 > setsockopt(sockfd, CSOCKET_IPPROTO_IP, CSOCKET_IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_drop_mcast: drop from mcast %s failed, errno = %d, errstr = %s\n",
                            c_word_to_ipv4(mcast_ipaddr), errno, strerror(errno));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_udp_sendto(const int sockfd, const UINT32 mcast_ipaddr, const UINT32 mcast_port, const UINT8 *data, const UINT32 dlen)
{
    struct sockaddr_in mcast_addr;
    ssize_t o_len;

    BSET(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(mcast_ipaddr));
    mcast_addr.sin_port = htons( atoi(c_word_to_port(mcast_port)) );

    if(0 > (o_len = sendto(sockfd, data, dlen, 0, (struct sockaddr*)&mcast_addr,sizeof(mcast_addr))))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_sendto: send %ld bytes to mcast %s:%ld failed, errno = %d, errstr = %s\n",
                            dlen, c_word_to_ipv4(mcast_ipaddr), mcast_port, errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_sendto: send %ld of %ld bytes to mcast %s:%ld done\n",
                        o_len, dlen, c_word_to_ipv4(mcast_ipaddr), mcast_port);
    return (EC_TRUE);
}

EC_BOOL csocket_udp_mcast_sendto(const int sockfd, const UINT32 mcast_ipaddr, const UINT32 mcast_port, const UINT8 *data, const UINT32 dlen)
{
    struct sockaddr_in mcast_addr;

    uint32_t tlen;/*total length*/
    uint32_t csize;/*send completed size*/
    uint16_t osize;/*send once size*/
    uint16_t seqno;

    /*make sure dlen is 32 bits only*/
    if(dlen != (dlen & 0xFFFFFFFF))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_udp_mcast_sendto: dlen %ld overflow\n", dlen);
        return (EC_FALSE);
    }

    tlen = UINT32_TO_INT32(dlen);

    BSET(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(mcast_ipaddr));
    mcast_addr.sin_port = htons( atoi(c_word_to_port(mcast_port)) );

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_mcast_sendto: send %ld bytes to mcast %s:%ld\n",
                        dlen, c_word_to_ipv4(mcast_ipaddr), mcast_port);

    /*one udp packet format: total len (4B)| packet len (2B) | seqno (2B) | data (packet len bytes)*/
    for(csize = 0, seqno = 0, osize = CSOCKET_UDP_PACKET_DATA_SIZE; csize < tlen; csize += osize, seqno ++)
    {
        uint8_t  udp_packet[CSOCKET_UDP_PACKET_HEADER_SIZE + CSOCKET_UDP_PACKET_DATA_SIZE];
        uint32_t counter;

        if(csize + osize > tlen)
        {
            osize = tlen - csize;
        }

        counter = 0;
        gdbPut32(udp_packet, &counter, tlen);
        gdbPut16(udp_packet, &counter, osize);
        gdbPut16(udp_packet, &counter, seqno);
        gdbPut8s(udp_packet, &counter, data + csize, osize);

        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_mcast_sendto: tlen %d, osize %d, seqno %d\n", tlen, osize, seqno);

        if(0 > sendto(sockfd, udp_packet, counter, 0, (struct sockaddr*)&mcast_addr,sizeof(mcast_addr)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_mcast_sendto: send %u bytes to mcast %s:%ld failed, errno = %d, errstr = %s\n",
                                counter, c_word_to_ipv4(mcast_ipaddr), mcast_port, errno, strerror(errno));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL csocket_udp_mcast_recvfrom(const int sockfd, const UINT32 mcast_ipaddr, const UINT32 mcast_port, UINT8 *data, const UINT32 max_dlen, UINT32 *dlen)
{
    struct sockaddr_in mcast_addr;
    socklen_t mcast_addr_len;

    CBITMAP  *cbitmap;
    uint32_t  csize;/*send completed size*/


    BSET(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(mcast_ipaddr));
    //mcast_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    mcast_addr.sin_port = htons( atoi(c_word_to_port(mcast_port)) );

    mcast_addr_len = sizeof(mcast_addr);

    cbitmap = NULL_PTR;
    csize   = 0;

    do
    {
        uint8_t   udp_packet[CSOCKET_UDP_PACKET_HEADER_SIZE + CSOCKET_UDP_PACKET_DATA_SIZE];

        uint32_t tlen;/*total length*/
        uint16_t osize;/*send once size*/
        uint16_t seqno;

        uint32_t counter;
        uint32_t offset;

        if(0 > recvfrom(sockfd, (void *)udp_packet, sizeof(udp_packet)/sizeof(udp_packet[0]), 0, (struct sockaddr *)&mcast_addr, &mcast_addr_len))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_mcast_recvfrom: recv from mcast %s:%ld failed, errno = %d, errstr = %s\n",
                                c_word_to_ipv4(mcast_ipaddr), mcast_port, errno, strerror(errno));
            cbitmap_free(cbitmap);/*also works when cbitmap is NULL_PTR*/
            return (EC_FALSE);
        }

        counter = 0;
        tlen  = gdbGet32(udp_packet, &counter);
        osize = gdbGet16(udp_packet, &counter);
        seqno = gdbGet16(udp_packet, &counter);

        if(NULL_PTR != cbitmap && EC_TRUE == cbitmap_check(cbitmap, seqno))
        {
            continue;
        }

        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_mcast_recvfrom: tlen %d, osize %d, seqno %d\n", tlen, osize, seqno);

        if(NULL_PTR == cbitmap)
        {
            uint32_t max_bits;

            max_bits = ((tlen + CSOCKET_UDP_PACKET_DATA_SIZE - 1)/ CSOCKET_UDP_PACKET_DATA_SIZE);
            cbitmap = cbitmap_new(max_bits);
            if(NULL_PTR == cbitmap)
            {
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_mcast_recvfrom: new cbitmap with max bits %d failed\n", max_bits);
                return (EC_FALSE);
            }

            /*so sorry for adjustment due to cbitmap_new will align the max bits to multiple of WORDSIZE :-(*/
            CBITMAP_MAX_BITS(cbitmap) = max_bits;
        }

        offset = seqno * CSOCKET_UDP_PACKET_DATA_SIZE;
        if(offset + osize > max_dlen)
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_udp_mcast_recvfrom: no enough room to accept %d bytes at offset %d\n", osize, offset);
            cbitmap_free(cbitmap);
            return (EC_FALSE);
        }

        BCOPY(udp_packet + counter, data + offset, osize);
        csize += osize;

        cbitmap_set(cbitmap, seqno);

        //cbitmap_print(cbitmap, LOGSTDOUT);
    }while(EC_FALSE == cbitmap_is_full(cbitmap));

    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_mcast_recvfrom: recv %d bytes from mcast %s:%ld\n",
                        csize, c_word_to_ipv4(mcast_ipaddr), mcast_port);

    cbitmap_free(cbitmap);
    (*dlen) = csize;
    return (EC_TRUE);
}

EC_BOOL csocket_udp_write(const int sockfd, const UINT32 ipaddr, const UINT32 port, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos)
{
    struct sockaddr_in udp_srv_addr;

    BSET(&udp_srv_addr, 0, sizeof(udp_srv_addr));
    udp_srv_addr.sin_family      = AF_INET;
    udp_srv_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(ipaddr));
    udp_srv_addr.sin_port        = htons(atoi(c_word_to_port(port)));

    for(;;)
    {
        UINT32   once_sent_len;
        ssize_t  sent_num;

        once_sent_len = out_buff_max_len - (*pos);
        if(0 == once_sent_len)
        {
            return (EC_TRUE);
        }

        once_sent_len = DMIN(once_max_size, once_sent_len);

        sent_num = sendto(sockfd, (void *)(out_buff + (*pos)), once_sent_len, 0, (struct sockaddr*)&udp_srv_addr, sizeof(udp_srv_addr));
        if(0 > sent_num)
        {
            return csocket_no_ierror(sockfd);
        }

        if(0 == sent_num )/*when ret = 0, no data was sent*/
        {
            return (EC_TRUE);
        }
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_write: sockfd %d sent out %ld bytes\n", sockfd, sent_num);
        (*pos) += (UINT32)sent_num;
    }

    return (EC_TRUE);
}

EC_BOOL csocket_udp_read(const int sockfd, const UINT32 ipaddr, const UINT32 port, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    struct sockaddr_in udp_srv_addr;
    size_t  once_recv_len;

    BSET(&udp_srv_addr, 0, sizeof(udp_srv_addr));
    udp_srv_addr.sin_family      = AF_INET;
    udp_srv_addr.sin_addr.s_addr = htonl(UINT32_TO_INT32(ipaddr));
    udp_srv_addr.sin_port        = htons(atoi(c_word_to_port(port)));

    once_recv_len = (size_t)(in_buff_expect_len - (*pos));
    if(0 >= once_recv_len)/*no free space to recv*/
    {
        return (EC_TRUE);
    }

    /*when ioctl error happen*/
    for(; 0 < once_recv_len; once_recv_len = (size_t)(in_buff_expect_len - (*pos)))
    {
        socklen_t udp_srv_addr_len;
        ssize_t  recved_num;

        udp_srv_addr_len = sizeof(udp_srv_addr);

        once_recv_len = DMIN(once_max_size, once_recv_len);

        recved_num = recvfrom(sockfd, (void *)(in_buff + (*pos)), once_recv_len, 0, (struct sockaddr *)&udp_srv_addr, &udp_srv_addr_len);
        if(0 > recved_num)
        {
            /*no data to recv or found error*/
            return csocket_no_ierror(sockfd);
        }

        if(0 == recved_num)
        {
            return (EC_TRUE);
        }

        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_udp_read: sockfd %d read in %d bytes\n",
                            sockfd, (uint32_t)recved_num);
        (*pos) += (UINT32)recved_num;
    }

    return (EC_TRUE);
}

EC_BOOL csocket_send_confirm(const int sockfd)
{
    if(do_log(SEC_0053_CSOCKET, 5))
    {
        sys_log(LOGSTDOUT, "csocket_send_confirm: start to send data on sockfd %d\n", sockfd);
        csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
    }

    if(-1 == send(sockfd, NULL_PTR, 0, 0) && EAGAIN == errno)
    {
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_send_confirm: sockfd %d connection confirmed\n", sockfd);
        return (EC_TRUE);
    }
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_send_confirm: sockfd %d errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
    return (EC_FALSE);
}

EC_BOOL csocket_recv_confirm(const int sockfd)
{
    if(do_log(SEC_0053_CSOCKET, 5))
    {
        sys_log(LOGSTDOUT, "csocket_recv_confirm: start to recv data on sockfd %d\n", sockfd);
        csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
    }

    if(-1 == recv(sockfd, NULL_PTR, 0, 0) && EAGAIN == errno)
    {
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_read_confirm: sockfd %d connection confirmed\n", sockfd);
        return (EC_TRUE);
    }
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_recv_confirm: errno = %d, errstr = %s\n", errno, strerror(errno));
    return (EC_FALSE);
}

/*get local ipaddr and port of sockfd*/
EC_BOOL csocket_ipaddr_and_port(const int sockfd, UINT32 *ipaddr, UINT32 *port)
{
    struct sockaddr_in sockaddr_in;
    socklen_t          sockaddr_len;

    sockaddr_len = sizeof(struct sockaddr_in);
    BSET(&sockaddr_in, 0, sockaddr_len);

    if(0 != getsockname(sockfd, (struct sockaddr *)&(sockaddr_in), &(sockaddr_len)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_ipaddr_and_port: getsockname of sockfd %d failed\n", sockfd);
        return (EC_FALSE);
    }

    if(NULL_PTR != ipaddr)
    {
        (*ipaddr) = c_ipv4_to_word((char *)c_inet_ntos(&(sockaddr_in.sin_addr)));
    }

    if(NULL_PTR != port)
    {
        (*port)   = c_inet_ntohs(sockaddr_in.sin_port);
    }

    return (EC_TRUE);
}

EC_BOOL csocket_connect_wait_ready(int sockfd)
{
    FD_CSET *fd_cset;
    int max_sockfd;
    int ret;
    int len;
    int err;
    struct timeval timeout;

    timeout.tv_sec  = 5;
    timeout.tv_usec = 0;

    max_sockfd = 0;

    fd_cset = safe_malloc(sizeof(FD_CSET), LOC_CSOCKET_0003);
    if(NULL_PTR == fd_cset)
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect_wait_ready: malloc FD_CSET with size %d failed\n",
                            (uint32_t)sizeof(FD_CSET));
        return (EC_FALSE);
    }

    csocket_fd_clean(fd_cset);
    csocket_fd_set(sockfd, fd_cset, &max_sockfd);
    if(EC_FALSE == csocket_select(max_sockfd + 1, fd_cset, NULL_PTR, NULL_PTR, &timeout, &ret))
    {
        safe_free(fd_cset, LOC_CSOCKET_0004);
        return (EC_FALSE);
    }

    len = sizeof(int);
    if(0 != getsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_ERROR, (char *)&err, (socklen_t *)&len))
    {
        safe_free(fd_cset, LOC_CSOCKET_0005);
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect_wait_ready: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return (EC_FALSE);
    }

    if(0 != err)
    {
        safe_free(fd_cset, LOC_CSOCKET_0006);
        return (EC_FALSE);
    }

    safe_free(fd_cset, LOC_CSOCKET_0007);
    return (EC_TRUE);
}

EC_BOOL csocket_connect(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd, UINT32 *client_ipaddr, UINT32 *client_port)
{
    struct sockaddr_in srv_addr;

    int sockfd;

    /* initialize the ip addr and port of server */
    if( EC_FALSE == csocket_client_addr_init( srv_ipaddr, srv_port, &srv_addr ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_connect: csocket_client_addr_init failed\n");
        return ( EC_FALSE );
    }

    /* create socket */
    sockfd = csocket_open( AF_INET, SOCK_STREAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_connect: socket error\n");
        return ( EC_FALSE );
    }

    /* note: optimization must before connect at server side*/
    if(EC_FALSE == csocket_optimize(sockfd, csocket_block_mode))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_connect: sockfd %d failed in some optimization\n", sockfd);
    }

    /* connect to server, connect timeout is default 75s */
    if(0 > connect(sockfd, (struct sockaddr *) &srv_addr, sizeof(struct sockaddr)) /*&& EINPROGRESS != errno && EINTR != errno*/)
    {
        int errcode;

        errcode = errno;

        switch(errcode)
        {
            case EACCES:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, write permission is denied on the socket file, or search permission is denied for one of the directories in the path prefix\n", sockfd);
                break;

            case EPERM:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, tried to connect to a broadcast address without having the socket broadcast flag enabled or the connection request failed because of a local firewall rule\n", sockfd);
                break;

            case EADDRINUSE:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, local address is already in use\n", sockfd);
                break;

            case EAFNOSUPPORT:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, The passed address not have the correct address family in its sa_family fiel\n", sockfd);
                break;

            case EADDRNOTAVAIL:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, non-existent interface was requested or the requested address was not local\n", sockfd);
                break;

            case EALREADY:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, the socket is non-blocking and a previous connection attempt has not yet been completed\n", sockfd);
                break;

            case EBADF:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, the file descriptor is not a valid index in the descriptor tabl\n", sockfd);
                break;

            case ECONNREFUSED:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, no one listening on remote %s:%ld\n", sockfd, c_word_to_ipv4(srv_ipaddr), srv_port);
                break;

            case EFAULT:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, the socket structure address is outside the user address space\n", sockfd);
                break;

            case EINPROGRESS:
                dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT, "warn:csocket_connect: sockfd %d is in progress\n", sockfd);
                if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode)
                {
                    csocket_nonblock_enable(sockfd);
                }
                *client_sockfd = sockfd;
                return ( EC_TRUE );

            case EINTR:
                dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT, "warn:csocket_connect: sockfd %d, the system call was interrupted by a signal that was caugh\n", sockfd);
                if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode)
                {
                    csocket_nonblock_enable(sockfd);
                }
                *client_sockfd = sockfd;
                return ( EC_TRUE );

            case EISCONN:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d is already connected\n", sockfd);
                break;

            case ENETUNREACH:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, network is unreachabl\n", sockfd);
                break;

            case ENOTSOCK:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, the file descriptor is not associated with a socket\n", sockfd);
                break;

            case ETIMEDOUT:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, timeout while attempting connection. The server may be too busy to accept new connection\n", sockfd);
                break;

            case EHOSTDOWN:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, host down\n", sockfd);
                break;

            case EHOSTUNREACH:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, No route to host\n", sockfd);
                break;

            default:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_connect: sockfd %d, unknown errno = %d\n", sockfd, errcode);
        }

        /*os error checking by shell command: perror <errno>*/
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_connect: sockfd %d connect error, errno = %d, errstr = %s\n", sockfd, errcode, strerror(errcode));
        csocket_tcpi_stat_print(LOGSTDERR, sockfd);

        close(sockfd);
        return ( EC_FALSE );
    }

    (*client_sockfd) = sockfd;

    csocket_ipaddr_and_port(sockfd, client_ipaddr, client_port);
    return ( EC_TRUE );
}

UINT32 csocket_state(const int sockfd)
{
    CSOCKET_TCPI info;
    socklen_t info_len;

    UINT32 state;

    if(ERR_FD == sockfd)
    {
        return ((UINT32)-1);
    }

    info_len = sizeof(CSOCKET_TCPI);
    if(0 != getsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_INFO, (char *)&info, &info_len))
    {
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_established: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return ((UINT32)-1);
    }

    state = info.tcpi_state;
    return (state);
}

const char *csocket_tcpi_stat_desc(const int sockfd)
{
    CSOCKET_TCPI info;
    socklen_t info_len;

    info_len = sizeof(CSOCKET_TCPI);
    if(0 != getsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_INFO, (char *)&info, &info_len))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_tcpi_stat_desc: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return ((const char *)"csocket_tcpi_stat_desc internal error");
    }

    return csocket_tcpi_stat(info.tcpi_state);
}

EC_BOOL csocket_is_established(const int sockfd)
{
    CSOCKET_TCPI info;
    socklen_t info_len;

    if(ERR_FD == sockfd)
    {
        return (EC_FALSE);
    }

    info_len = sizeof(CSOCKET_TCPI);
    if(0 != getsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_INFO, (char *)&info, &info_len))
    {
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_established: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return (EC_FALSE);
    }

    switch(info.tcpi_state)
    {
        case CSOCKET_TCP_ESTABLISHED:
            //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_established: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_TRUE);
        case CSOCKET_TCP_SYN_SENT   :
        case CSOCKET_TCP_SYN_RECV   :
        case CSOCKET_TCP_FIN_WAIT1  :
        case CSOCKET_TCP_FIN_WAIT2  :
        case CSOCKET_TCP_TIME_WAIT  :
        case CSOCKET_TCP_CLOSE      :
        case CSOCKET_TCP_CLOSE_WAIT :
        case CSOCKET_TCP_LAST_ACK   :
        case CSOCKET_TCP_LISTEN     :
        case CSOCKET_TCP_CLOSING    :
            //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_established: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
    }
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_established: unknown tcpi_stat = %d\n", info.tcpi_state);
    return (EC_FALSE);

}

EC_BOOL csocket_is_connected(const int sockfd)
{
    CSOCKET_TCPI info;
    socklen_t info_len;

    if(ERR_FD == sockfd)
    {
        return (EC_FALSE);
    }

    info_len = sizeof(CSOCKET_TCPI);
    if(0 != getsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_INFO, (char *)&info, &info_len))
    {
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return (EC_FALSE);
    }

    //dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_is_connected: called for sockfd %d\n", sockfd);
    switch(info.tcpi_state)
    {
        case CSOCKET_TCP_ESTABLISHED:
            //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_TRUE);
        case CSOCKET_TCP_SYN_SENT   :
            //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_TRUE);
        case CSOCKET_TCP_SYN_RECV   :
            //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_TRUE);
        case CSOCKET_TCP_FIN_WAIT1  :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
        case CSOCKET_TCP_FIN_WAIT2  :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
        case CSOCKET_TCP_TIME_WAIT  :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
        case CSOCKET_TCP_CLOSE      :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
        case CSOCKET_TCP_CLOSE_WAIT :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
        case CSOCKET_TCP_LAST_ACK   :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
        case CSOCKET_TCP_LISTEN     :
            //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_TRUE);
        case CSOCKET_TCP_CLOSING    :
            dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: sockfd %d, tcpi state = %s\n", sockfd, csocket_tcpi_stat(info.tcpi_state));
            return (EC_FALSE);
    }
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_connected: unknown tcpi_stat = %d\n", info.tcpi_state);
    return (EC_FALSE);
}

EC_BOOL csocket_is_closed(const int sockfd)
{
    CSOCKET_TCPI info;
    socklen_t info_len;

    if(ERR_FD == sockfd)
    {
        return (EC_FALSE);
    }

    info_len = sizeof(CSOCKET_TCPI);
    if(0 != getsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_INFO, (char *)&info, &info_len))
    {
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_closed: sockfd %d, errno = %d, errstr = %s\n", sockfd, errno, strerror(errno));
        return (EC_FALSE);
    }

    switch(info.tcpi_state)
    {
        case CSOCKET_TCP_ESTABLISHED:
        case CSOCKET_TCP_SYN_SENT   :
        case CSOCKET_TCP_SYN_RECV   :
            return (EC_FALSE);
        case CSOCKET_TCP_FIN_WAIT1  :
        case CSOCKET_TCP_FIN_WAIT2  :
        case CSOCKET_TCP_TIME_WAIT  :
        case CSOCKET_TCP_CLOSE      :
        case CSOCKET_TCP_CLOSE_WAIT :
        case CSOCKET_TCP_LAST_ACK   :
            return (EC_TRUE);
        case CSOCKET_TCP_LISTEN     :
            return (EC_FALSE);
        case CSOCKET_TCP_CLOSING    :
            return (EC_TRUE);
    }
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_is_closed: unknown tcpi_stat = %d\n", info.tcpi_state);
    return (EC_FALSE);

}

EC_BOOL csocket_select(const int sockfd_boundary, FD_CSET *read_sockfd_set, FD_CSET *write_sockfd_set, FD_CSET *except_sockfd_set, struct timeval *timeout, int *retval)
{
    int ret;

    ret = select(sockfd_boundary,
                (NULL_PTR == read_sockfd_set)   ? NULL_PTR : SOCKFD_SET(read_sockfd_set),
                (NULL_PTR == write_sockfd_set)  ? NULL_PTR : SOCKFD_SET(write_sockfd_set),
                (NULL_PTR == except_sockfd_set) ? NULL_PTR : SOCKFD_SET(except_sockfd_set),
                timeout);

    (*retval) = ret;
    if(0 > ret)/*error occur*/
    {
        return csocket_no_ierror(sockfd_boundary);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_shutdown( const int sockfd, const int flag )
{
    int ret;

    ret = shutdown( sockfd, flag );
    if ( 0 > ret )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_shutdown: failed to close sockfd %d direction %d\n", sockfd, flag);
        return ( EC_FALSE );
    }

    return ( EC_TRUE );
}

int csocket_open(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_open: open socket failed, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
        return (ERR_FD);
    }

    if(1)
    {
        if( 0 > fcntl(sockfd, F_SETFD, FD_CLOEXEC))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_open: set sockfd %d to FD_CLOEXEC failed, errno = %d, errstr = %s\n",
                               sockfd, errno, strerror(errno));
            close(sockfd);
            return (ERR_FD);
        }
    }
    return ( sockfd );
}

EC_BOOL csocket_close( const int sockfd )
{
    if(ERR_FD == sockfd)
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_close: why try to close sockfd %d ?\n", sockfd);
        return (EC_FALSE);
    }

#if 0 /*csocket_is_connected and csocket_tcpi_stat_print are not adaptive to UDP socket*/
    if(EC_TRUE == csocket_is_connected(sockfd))
    {
        close( sockfd );
        dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT,"[DEBUG] csocket_close: close sockfd %d\n", sockfd);
        return (EC_TRUE);
    }

    if(do_log(SEC_0053_CSOCKET, 5))
    {
        sys_log(LOGSTDOUT, "csocket_close: tcpi stat is: \n");
        csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
    }
#endif

    close(sockfd);
    dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT,"warn:csocket_close: force close sockfd %d\n", sockfd);

    return ( EC_TRUE );
}

int csocket_errno()
{
    return errno;
}

EC_BOOL csocket_is_eagain()
{
    if(EAGAIN == errno)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csocket_no_ierror(const int sockfd)
{
    int err;

    err = errno;
    if(EINPROGRESS == err || EAGAIN == err || EWOULDBLOCK == err || EINTR == err)
    {
        return (EC_TRUE); /*no error*/
    }
    dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "warn:csocket_no_ierror: sockfd %d, errno = %d, errstr = %s\n", sockfd, err, strerror(err));
    return (EC_FALSE);/*found error*/
}

EC_BOOL csocket_isend(const int sockfd, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    ssize_t ret;
    UINT32  once_sent_len;

    if(out_buff_max_len < (*position))/*debug*/
    {
        dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT, "error:csocket_isend: out_buff_max_len %ld < pos %ld\n", out_buff_max_len, (*position));
        return (EC_FALSE);
    }

    //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_isend: start to send data on sockfd %d: beg: max len = %ld, position = %ld\n", sockfd, out_buff_max_len, *position);
    //csocket_tcpi_stat_print(LOGSTDOUT, sockfd);

    once_sent_len = out_buff_max_len - (*position);
    if(0 == once_sent_len)
    {
        return (EC_TRUE);
    }

    once_sent_len = DMIN(CSOCKET_SEND_ONCE_MAX_SIZE, once_sent_len);

    ret = write(sockfd, (void *)(out_buff + (*position)), once_sent_len);
    if(0 <= ret )/*when ret = 0, no data was sent*/
    {
        (*position) += (ret);
        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDNULL, "csocket_isend: end to send data on sockfd %d: end: max len = %ld, position = %ld\n", sockfd, out_buff_max_len, *position);
        return (EC_TRUE);
    }
    /*when ret = -1, error happen*/
    dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDNULL, "warn:csocket_isend: sockfd %d, errno = %d, errstr = %s, max len %ld, pos %ld\n",
                        sockfd, errno, strerror(errno), out_buff_max_len, (*position));
    return csocket_no_ierror(sockfd);
}

EC_BOOL csocket_irecv(const int sockfd, UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position)
{
    ssize_t ret;
    UINT32  once_recv_len;

    if(in_buff_max_len < (*position))/*debug*/
    {
        dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT, "error:csocket_irecv: out_buff_max_len %ld < pos %ld\n", in_buff_max_len, (*position));
        return (EC_FALSE);
    }

    //dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_irecv: start to send data on sockfd %d: beg: max len = %ld, position = %ld\n", sockfd, in_buff_max_len, *position);
    //csocket_tcpi_stat_print(LOGSTDOUT, sockfd);

    once_recv_len = in_buff_max_len - (*position);
    if(0 == once_recv_len)/*no free space to recv*/
    {
        return (EC_TRUE);
    }

    once_recv_len = DMIN(CSOCKET_RECV_ONCE_MAX_SIZE, once_recv_len);
    ret = read(sockfd, (void *)(in_buff + (*position)), once_recv_len);
    if(0 <= ret )
    {
        (*position) += (ret);
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDNULL, "[DEBUG] csocket_irecv: end to recv data on sockfd %d: end: max len = %ld, position = %ld, ret = %d\n",
                            sockfd, in_buff_max_len, *position, (uint32_t)ret);

        return (EC_TRUE);
    }
    dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDNULL, "warn:csocket_irecv: sockfd %d, errno = %d, errstr = %s, max len %ld, pos %ld\n",
                        sockfd, errno, strerror(errno), in_buff_max_len, (*position));
    return csocket_no_ierror(sockfd);
}

EC_BOOL csocket_send(const int sockfd, const UINT8 *out_buff, const UINT32 out_buff_expect_len)
{
    UINT32 pos;

    pos = 0;

    while(pos < out_buff_expect_len)
    {
        if(EC_FALSE == csocket_is_connected(sockfd))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_send: sockfd %d was broken\n", sockfd);
            return (EC_FALSE);
        }

        if(EC_FALSE == csocket_isend(sockfd, out_buff, out_buff_expect_len, &pos))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_send: isend on sockfd %d failed where expect %ld, pos %ld\n",
                               sockfd, out_buff_expect_len, pos);
            return (EC_FALSE);
        }
        //dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_send: out_buff_expect_len %ld, pos %ld\n", out_buff_expect_len, pos);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_recv(const int sockfd, UINT8 *in_buff, const UINT32 in_buff_expect_len)
{
    UINT32 pos;

    pos = 0;

    while(pos < in_buff_expect_len)
    {
        if(EC_FALSE == csocket_is_connected(sockfd))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_recv: sockfd %d was broken\n", sockfd);
            return (EC_FALSE);
        }

        if(EC_FALSE == csocket_irecv(sockfd, in_buff, in_buff_expect_len, &pos))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_recv: irecv on sockfd %d failed where expect %ld, pos %ld\n",
                                sockfd, in_buff_expect_len, pos);
            return (EC_FALSE);
        }
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDNULL, "[DEBUG] csocket_recv: in_buff_expect_len %ld, pos %ld\n", in_buff_expect_len, pos);
    }
    return (EC_TRUE);
}

/*write until all data out or no further data can be sent out at present*/
EC_BOOL csocket_write(const int sockfd, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos)
{
    for(;;)
    {
        UINT32   once_sent_len;
        ssize_t  sent_num;

        once_sent_len = out_buff_max_len - (*pos);
        if(0 == once_sent_len)
        {
            return (EC_TRUE);
        }

        once_sent_len = DMIN(once_max_size, once_sent_len);

        sent_num = write(sockfd, (void *)(out_buff + (*pos)), once_sent_len);
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_write: "
                            "sockfd %d sent_num = %ld, tcpi %s, nonblock: %s\n",
                            sockfd, sent_num, csocket_tcpi_stat_desc(sockfd),
                            c_bool_str(csocket_is_nonblock(sockfd)));
        if(0 > sent_num)
        {
            return csocket_no_ierror(sockfd);
        }

        if(0 == sent_num )/*when ret = 0, no data was sent*/
        {
            return (EC_TRUE);
        }
        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_write: sockfd %d sent out %ld bytes\n", sockfd, sent_num);
        (*pos) += (UINT32)sent_num;
    }
    return (EC_TRUE);
}

/*fd is the regular file description, pos is the offset for this fd*/
EC_BOOL csocket_sendfile(const int sockfd, const int fd, const UINT32 max_len, UINT32 *pos)
{
    for(;;)
    {
        UINT32   once_sent_len;
        ssize_t  sent_num;
        off_t    offset;

        once_sent_len = max_len - (*pos);
        if(0 == once_sent_len)
        {
            return (EC_TRUE);
        }

        offset = (*pos);

        sent_num = sendfile(sockfd, fd, &offset, once_sent_len);
        if(0 > sent_num)
        {
            return csocket_no_ierror(sockfd);
        }

        if(0 == sent_num )/*when ret = 0, no data was sent*/
        {
            return (EC_TRUE);
        }

        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_sendfile: fd %d, from %ld to %ld, sent out %ld bytes\n", fd, (*pos), offset, sent_num);
        (*pos) += (UINT32)sent_num;
    }
    return (EC_TRUE);
}

/*read until all data ready or no further data to recv at present*/
EC_BOOL csocket_read(const int sockfd, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    size_t  once_recv_len;
    size_t  need_recv_len;

    once_recv_len = (size_t)(in_buff_expect_len - (*pos));
    if(0 >= once_recv_len)/*no free space to recv*/
    {
        return (EC_TRUE);
    }

    if(0 == ioctl(sockfd, FIONREAD, &need_recv_len))
    {
        ssize_t  recved_num;

        once_recv_len = DMIN(need_recv_len, once_recv_len);

        recved_num = read(sockfd, (void *)(in_buff + (*pos)), once_recv_len);
        if(0 > recved_num)
        {
            /*no data to recv or found error*/
            return csocket_no_ierror(sockfd);
        }

        if(0 == recved_num)
        {
            return (EC_TRUE);
        }

        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_read: sockfd %d read in %d bytes while need_recv_len is %d\n",
                        sockfd, (uint32_t)recved_num, (uint32_t)need_recv_len);
        (*pos) += (UINT32)recved_num;

        return (EC_TRUE);
    }

    /*when ioctl error happen*/
    for(; 0 < once_recv_len; once_recv_len = (size_t)(in_buff_expect_len - (*pos)))
    {

        ssize_t  recved_num;

        once_recv_len = DMIN(once_max_size, once_recv_len);

        recved_num = read(sockfd, (void *)(in_buff + (*pos)), once_recv_len);
        if(0 > recved_num)
        {
            /*no data to recv or found error*/
            return csocket_no_ierror(sockfd);
        }

        if(0 == recved_num)
        {
            return (EC_TRUE);
        }

        dbg_log(SEC_0053_CSOCKET, 9)(LOGSTDOUT, "[DEBUG] csocket_read: sockfd %d read in %d bytes\n",
                    sockfd, (uint32_t)recved_num);
        (*pos) += (UINT32)recved_num;
    }

    return (EC_TRUE);
}

/*to fix a incomplete task_node, when complete, return EC_TRUE, otherwise, return EC_FALSE yet*/
EC_BOOL csocket_cnode_fix_task_node(CSOCKET_CNODE *csocket_cnode, TASK_NODE *task_node)
{
    csocket_cnode_recv(csocket_cnode, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node)));

    /*when complete csocket_request, return EC_TRUE*/
    if(TASK_NODE_BUFF_LEN(task_node) == TASK_NODE_BUFF_POS(task_node))
    {
        return (EC_TRUE);
    }
    /*otherwise*/
    return (EC_FALSE);
}

UINT32 csocket_encode_actual_size()
{
    if(0 == g_tmp_encode_size)
    {
        TASK_BRD        *task_brd;

        task_brd = task_brd_default_get();
        /**
        *
        *   note: here we cannot call cmpi_encode_csocket_status_size to determine the actual encode size
        *   because xxx_size functions just give a estimated size but not the actual encoded size!
        *
        *   if make size = cmpi_encode_csocket_status_size(), the size may be greater than the crbuff_total_read_len,
        *   thus, terrible things happen: you would never fetch the data from crbuff until next data stream from remote
        *   reaches local and meet the size length ...
        *
        **/
#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
        cmpi_encode_uint32_size(TASK_BRD_COMM(task_brd), (UINT32)0, &g_tmp_encode_size);/*len*/
        cmpi_encode_uint32_size(TASK_BRD_COMM(task_brd), (UINT32)0, &g_tmp_encode_size);/*tag*/
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
        cmpi_encode_uint32_compressed_uint32_t_size(TASK_BRD_COMM(task_brd), (UINT32)0, &g_tmp_encode_size);/*len*/
        cmpi_encode_uint32_compressed_uint8_t_size(TASK_BRD_COMM(task_brd), (UINT32)0, &g_tmp_encode_size);/*tag*/
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    }

    return (g_tmp_encode_size);
}

UINT32 xmod_node_encode_actual_size()
{
    /*do once only*/
    if(0 == g_xmod_node_tmp_encode_size)
    {
        TASK_BRD    *task_brd;

        UINT8       *out_buff;
        UINT32       out_buff_max_len;
        UINT32      *position;

        task_brd = task_brd_default_get();
        /**
        *
        *   note: here we cannot call cmpi_encode_xmod_node_size to determine the actual encode size
        *   because xxx_size functions just give a estimated size but not the actual encoded size!
        *
        *   if make size = cmpi_encode_xmod_node_size(), the size may be greater than the crbuff_total_read_len,
        *   thus, terrible things happen: you would never fetch the data from crbuff until next data stream from remote
        *   reaches local and meet the size length ...
        *
        **/
        out_buff         = (UINT8 *)g_xmod_node_tmp_encode_buff;
        out_buff_max_len = sizeof(g_xmod_node_tmp_encode_buff)/sizeof(g_xmod_node_tmp_encode_buff[0]);
        position         = &g_xmod_node_tmp_encode_size;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
        cmpi_encode_uint32(TASK_BRD_COMM(task_brd), /*tcid*/(UINT32)0xFFFFFFFF, out_buff, out_buff_max_len, position);
        cmpi_encode_uint32(TASK_BRD_COMM(task_brd), /*comm*/(UINT32)0x000000FF, out_buff, out_buff_max_len, position);
        cmpi_encode_uint32(TASK_BRD_COMM(task_brd), /*size*/(UINT32)0x000000FF, out_buff, out_buff_max_len, position);
        cmpi_encode_uint32(TASK_BRD_COMM(task_brd), /*port*/(UINT32)0xFFFFFFFF, out_buff, out_buff_max_len, position);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/
#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
        cmpi_encode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), /*tcid*/(UINT32)0xFFFFFFFF, out_buff, out_buff_max_len, position);
        cmpi_encode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd) , /*comm*/(UINT32)0x000000FF, out_buff, out_buff_max_len, position);
        cmpi_encode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd) , /*size*/(UINT32)0x000000FF, out_buff, out_buff_max_len, position);
        cmpi_encode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), /*port*/(UINT32)0xFFFFFFFF, out_buff, out_buff_max_len, position);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/
    }

    return (g_xmod_node_tmp_encode_size);
}

/*fetch a complete or incomplete csocket_request, caller should check the result*/
TASK_NODE *csocket_fetch_task_node(CSOCKET_CNODE *csocket_cnode)
{
    UINT32    size;
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    size = csocket_encode_actual_size();

    if(CSOCKET_CNODE_PKT_POS(csocket_cnode) < size)
    {
        if(EC_FALSE == csocket_irecv(CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                      CSOCKET_CNODE_PKT_HDR(csocket_cnode),
                                      size,
                                      &(CSOCKET_CNODE_PKT_POS(csocket_cnode)))
          )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_fetch_task_node: csocket irecv failed on sockfd %d where pkt pos %ld\n",
                                CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_PKT_POS(csocket_cnode));
            return (NULL_PTR);
        }
    }

    if(CSOCKET_CNODE_PKT_POS(csocket_cnode) >= size)
    {
        UINT32  pos;

        UINT32  len;
        UINT32  tag;
        UINT8  *out_buff;
        UINT32  out_size;

        TASK_NODE *task_node;

        out_buff = CSOCKET_CNODE_PKT_HDR(csocket_cnode);
        out_size = CSOCKET_CNODE_PKT_POS(csocket_cnode);

        pos = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
        cmpi_decode_uint32(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &len);
        cmpi_decode_uint32(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &tag);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
        cmpi_decode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &len);
        cmpi_decode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd) , out_buff, out_size, &pos, &tag);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

        if(CSOCKET_BUFF_MAX_LEN <= len)/*should never overflow 1 GB*/
        {
            CSOCKET_CNODE_SET_DISCONNECTED(csocket_cnode);
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_fetch_task_node: disconnect sockfd %d due to invalid len 0x%lx\n",
                                                    CSOCKET_CNODE_SOCKFD(csocket_cnode), len);
            return (NULL_PTR);
        }

        task_node = task_node_new(len, LOC_CSOCKET_0008);
        if(NULL_PTR == task_node)
        {
            CSOCKET_CNODE_SET_DISCONNECTED(csocket_cnode); /*something wrong. Feb 24,2018*/
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_fetch_task_node: new task_node with %ld bytes failed\n", len);
            return (NULL_PTR);
        }

        TASK_NODE_TAG(task_node) = tag;

        dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "[DEBUG] csocket_fetch_task_node: sockfd %d, len 0x%lx, tag 0x%lx, new task_node %p\n",
                                                CSOCKET_CNODE_SOCKFD(csocket_cnode), len, tag, task_node);

        /*move the probed buff to task_node*/
        BCOPY(out_buff, TASK_NODE_BUFF(task_node), out_size);
        TASK_NODE_BUFF_POS(task_node)        = out_size;
        CSOCKET_CNODE_PKT_POS(csocket_cnode) = 0;

        csocket_cnode_recv(csocket_cnode, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node)));

        return (task_node);
    }
    return (NULL_PTR);
}

EC_BOOL csocket_isend_task_node(CSOCKET_CNODE *csocket_cnode, TASK_NODE *task_node)
{
    if(EC_FALSE == CSOCKET_CNODE_IS_CONNECTED(csocket_cnode))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_request_isend: sockfd %d is disconnected\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }
    if(EC_FALSE == csocket_cnode_send(csocket_cnode, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node))))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_request_isend: sockfd %d isend failed\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_irecv_task_node(CSOCKET_CNODE *csocket_cnode, TASK_NODE *task_node)
{
    if(EC_FALSE == csocket_is_connected(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_request_irecv: tcid %s sockfd %d is disconnected\n",
                            TASK_NODE_RECV_TCID_STR(task_node),
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(EC_FALSE == csocket_cnode_recv(csocket_cnode,
                                  TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node))))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_request_irecv: tcid %s sockfd %d irecv failed where data addr = %p, len = %ld, pos = %ld\n",
                        TASK_NODE_RECV_TCID_STR(task_node),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        TASK_NODE_BUFF(task_node),
                        TASK_NODE_BUFF_LEN(task_node),
                        TASK_NODE_BUFF_POS(task_node));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_srv_start( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *srv_sockfd )
{
    if(EC_FALSE == csocket_listen(srv_ipaddr, srv_port, srv_sockfd))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_srv_start: failed to listen on port %ld\n",srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_srv_start: start server %d on port %s:%ld\n", (*srv_sockfd), c_word_to_ipv4(srv_ipaddr), srv_port);

    if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode && EC_FALSE == csocket_is_nonblock(*srv_sockfd))
    {
        csocket_nonblock_enable(*srv_sockfd);
    }

    if(CSOCKET_IS_BLOCK_MODE == csocket_block_mode && EC_TRUE == csocket_is_nonblock(*srv_sockfd))
    {
        csocket_nonblock_disable(*srv_sockfd);
    }
    return (EC_TRUE);
}

EC_BOOL csocket_srv_end(const int srv_sockfd)
{
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_srv_end: stop server %d\n", srv_sockfd);
    csocket_close(srv_sockfd);

    return (EC_TRUE);
}

EC_BOOL csocket_client_start( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd, UINT32 *client_ipaddr, UINT32 *client_port )
{
    if(EC_FALSE == csocket_connect( srv_ipaddr, srv_port , csocket_block_mode, client_sockfd, client_ipaddr, client_port ))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDNULL, "error:csocket_client_start: client failed to connect server %s:%ld\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDNULL, "csocket_client_start: start client %d connecting to server %s:%ld\n",
                        (*client_sockfd), c_word_to_ipv4(srv_ipaddr), srv_port);
    return (EC_TRUE);
}

EC_BOOL csocket_client_end(const int client_sockfd)
{
    csocket_close(client_sockfd);
    dbg_log(SEC_0053_CSOCKET, 5)(LOGSTDOUT, "csocket_client_end: stop client %d\n", client_sockfd);
    return (EC_TRUE);
}

EC_BOOL csocket_unix_optimize(int sockfd)
{
    EC_BOOL ret;

    ret = EC_TRUE;
    /* optimization 1: disalbe Nagle Algorithm */
    if(0)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, CSOCKET_TCP_NODELAY, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to disable Nagle Algo\n", sockfd);
            ret = EC_FALSE;
        }
    }

#ifdef __linux__
    /*optimization: quick ack*/
    if(0)
    {
        int flag;
        flag = 1;
        if(0 != setsockopt(sockfd, CSOCKET_IPPROTO_TCP, TCP_QUICKACK, (char *) &flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_unix_optimize: sockfd %d failed to enable QUICKACK\n", sockfd);
            ret = EC_FALSE;
        }
    }
#endif/*__linux__*/
    /* optimization 2.1: when flag > 0, set SEND_BUFF size per packet - Flow Control*/
    /* optimization 2.2: when flag = 0, the data buff to send will NOT copy to system buff but send out directly*/
    if(1)
    {
        int flag;
        flag = CSOCKET_SO_SNDBUFF_SIZE;
        if(0 <= flag && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDBUF, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set SEND BUFF to %d\n", sockfd, flag);
            ret = EC_FALSE;
        }
    }

    /* optimization 3.1: when flag > 0, set RECV_BUFF size per packet - Flow Control*/
    /* optimization 3.2: when flag = 0, the data buff to recv will NOT copy from system buff but recv in directly*/
    if(1)
    {
        int flag;
        flag = CSOCKET_SO_RCVBUFF_SIZE;
        if(0 <= flag && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVBUF, (char *)&flag, sizeof(flag)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set RECV BUFF to %d\n", sockfd, flag);
            ret = EC_FALSE;
        }
    }

    /* optimization 4: set KEEPALIVE*/
    /*note: CSOCKET_SO_KEEPALIVE is only for TCP protocol but not for UDP, hence some guys need to implement heartbeat mechanism */
    /*in application level to cover both TCP and UDP*/
    if(0)
    {
        int flag;
        int keep_idle;
        int keep_interval;
        int keep_count;

        flag = 1;/*1: enable KEEPALIVE, 0: disable KEEPALIVE*/
        keep_idle     = CSOCKET_TCP_KEEPIDLE_NSEC; /*if no data transmission in 10 seconds, start to check socket*/
        keep_interval = CSOCKET_TCP_KEEPINTVL_NSEC;  /*send heartbeat packet in interval 5 seconds*/
        keep_count    = CSOCKET_TCP_KEEPCNT_TIMES;  /*send heartbeat packet up to 3 times, if some heartbeat recv ack, then stop. otherwise, regard socket is disconnected*/
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_KEEPALIVE, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set KEEPALIVE\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPIDLE, (char *)&keep_idle, sizeof(keep_idle) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set KEEPIDLE\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPINTVL, (char *)&keep_interval, sizeof(keep_interval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set KEEPINTVL\n", sockfd);
            ret = EC_FALSE;
        }

        if( 1 == flag && 0 != setsockopt( sockfd, CSOCKET_SOL_TCP, CSOCKET_TCP_KEEPCNT, (char *)&keep_count, sizeof(keep_count) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set KEEPCNT\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /* optimization 5: set REUSEADDR*/
    if(1)
    {
        int flag;
        flag = 1;
        if( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_REUSEADDR, (char *)&flag, sizeof(flag) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set REUSEADDR\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /* optimization 6: set SEND TIMEOUT. NOTE: the timeout not working for socket connect op*/
    if(0)
    {
        struct timeval timeout;
        time_t usecs = CSOCKET_SO_SNDTIMEO_NSEC * 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_optimize: sockfd %d failed to set SEND TIMEOUT to %ld usecs\n", sockfd, usecs);
            ret = EC_FALSE;
        }
    }

    /* optimization 7: set RECV TIMEOUT. NOTE: the timeout not working for socket connect op*/
    if(0)
    {
        struct timeval timeout;
        time_t usecs = CSOCKET_SO_RCVTIMEO_NSEC * 1000;

        timeout.tv_sec  = usecs / 1000;
        timeout.tv_usec = usecs % 1000;
        if ( 0 != setsockopt( sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval) ) )
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_unix_optimize: sockfd %d failed to set RECV TIMEOUT to %ld usecs\n", sockfd, usecs);
            ret = EC_FALSE;
        }
    }

    /* optimization 8: set NONBLOCK*/
    if(1)
    {
        int flag;

        flag = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, O_NONBLOCK | flag);
    }

    /*optimization 9: disable linger, i.e., send close socket, stop sending/recving at once*/
    if(1)
    {
        struct linger linger_disable;
        linger_disable.l_onoff  = 0; /*disable*/
        linger_disable.l_linger = 0; /*stop after 0 second, i.e., stop at once*/

        if( 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_LINGER, (const char*)&linger_disable, sizeof(struct linger)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_unix_optimize: sockfd %d failed to disable linger\n", sockfd);
            ret = EC_FALSE;
        }
    }

    /*optimization 10: sets the minimum number of bytes to process for socket input operations. The default value for CSOCKET_SO_RCVLOWAT is 1*/
    if(0)
    {
        int  recv_lowat_size;

        recv_lowat_size = CSOCKET_SO_RCVLOWAT_SIZE;
        if(0 < recv_lowat_size && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_RCVLOWAT, (const char *) &recv_lowat_size, sizeof(int)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_unix_optimize: sockfd %d failed to set CSOCKET_SO_RCVLOWAT to %d\n", sockfd, recv_lowat_size);
            ret = EC_FALSE;
        }
    }

    /*optimization 11: Sets the minimum number of bytes to process for socket output operations*/
    if(0)
    {
        int  send_lowat_size;

        send_lowat_size = CSOCKET_SO_SNDLOWAT_SIZE;
        if(0 < send_lowat_size && 0 != setsockopt(sockfd, CSOCKET_SOL_SOCKET, CSOCKET_SO_SNDLOWAT, (const char *) &send_lowat_size, sizeof(int)))
        {
            dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"warn:csocket_unix_optimize: sockfd %d failed to set CSOCKET_SO_SNDLOWAT to %d\n", sockfd, send_lowat_size);
            ret = EC_FALSE;
        }
    }

    return (ret);
}

/*
struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108];
}
*/
STATIC_CAST static EC_BOOL csocket_unix_srv_addr_init( const UINT32 srv_ipaddr, const UINT32 srv_port, struct sockaddr_un *srv_addr, size_t *srv_addr_len )
{
    size_t len;

    srv_addr->sun_family      = AF_UNIX;

    len = sizeof(srv_addr->sun_path)/sizeof(srv_addr->sun_path[0]);

    bzero(srv_addr->sun_path, len);
    /*anonymous mode: the first byte is '\0'*/
    //snprintf(srv_addr->sun_path + 1, len - 1, "unix@%s:%ld", c_word_to_ipv4(srv_ipaddr), srv_port);
    snprintf(srv_addr->sun_path, len, "/tmp/unix@%s:%ld", c_word_to_ipv4(srv_ipaddr), srv_port);

    (*srv_addr_len) = sizeof(struct sockaddr_un) - len + strlen(srv_addr->sun_path);

    return  ( EC_TRUE );
}

STATIC_CAST static EC_BOOL csocket_unix_srv_addr_unlink( struct sockaddr_un *srv_addr )
{
    unlink(srv_addr->sun_path);
    return (EC_TRUE);
}

EC_BOOL csocket_unix_listen( const UINT32 srv_ipaddr, const UINT32 srv_port, int *srv_sockfd )
{
    struct sockaddr_un srv_addr;
    size_t srv_addr_len;
    int sockfd;

    /* init socket addr structer */
    csocket_unix_srv_addr_init( srv_ipaddr, srv_port, &srv_addr, &srv_addr_len);

    csocket_unix_srv_addr_unlink(&srv_addr);

    /* create socket */
    sockfd = csocket_open( AF_UNIX, SOCK_STREAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_unix_listen: tcp socket failed, errno = %d, errstr = %s\n", errno, strerror(errno));
        return ( EC_FALSE );
    }


    /* note: optimization must before listen at server side*/
    if(EC_FALSE == csocket_unix_optimize(sockfd))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_listen: sockfd %d failed in some optimization\n", sockfd);
    }

    //csocket_nonblock_disable(sockfd);

    if ( 0 !=  bind( sockfd, (struct sockaddr *)&srv_addr, srv_addr_len ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_unix_listen: bind failed, errno = %d, errstr = %s\n", errno, strerror(errno));
        close(sockfd);
        return ( EC_FALSE );
    }

    /* create listen queues */
    if( 0 !=  listen( sockfd, CSOCKET_BACKLOG) )/*SOMAXCONN = 128 is a system constant*/
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_unix_listen: listen failed, errno = %d, errstr = %s\n", errno, strerror(errno));
        close(sockfd);
        return ( EC_FALSE );
    }

    *srv_sockfd = sockfd;

    return ( EC_TRUE );
}

STATIC_CAST static EC_BOOL csocket_unix_client_addr_init( const UINT32 srv_ipaddr, const UINT32 srv_port, struct sockaddr_un *srv_addr, size_t *srv_addr_len)
{
    size_t len;

    srv_addr->sun_family      = AF_UNIX;

    len = sizeof(srv_addr->sun_path)/sizeof(srv_addr->sun_path[0]);

    bzero(srv_addr->sun_path, len);
    /*anonymous mode: the first byte is '\0'*/
    //snprintf(srv_addr->sun_path + 1, len - 1, "unix@%s:%ld", c_word_to_ipv4(srv_ipaddr), srv_port);
    snprintf(srv_addr->sun_path, len, "/tmp/unix@%s:%ld", c_word_to_ipv4(srv_ipaddr), srv_port);

    (*srv_addr_len) = sizeof(struct sockaddr_un) - len + strlen(srv_addr->sun_path);

    return  ( EC_TRUE );
}

EC_BOOL csocket_unix_connect( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd )
{
    struct sockaddr_un srv_addr;
    size_t srv_addr_len;

    int sockfd;

    /* initialize the ip addr and port of server */
    if( EC_FALSE == csocket_unix_client_addr_init( srv_ipaddr, srv_port, &srv_addr, &srv_addr_len ) )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_unix_connect: csocket_client_addr_init failed\n");
        return ( EC_FALSE );
    }

    /* create socket */
    sockfd = csocket_open( AF_UNIX, SOCK_STREAM, 0 );
    if ( 0 > sockfd )
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "error:csocket_unix_connect: socket error\n");
        return ( EC_FALSE );
    }

    /* note: optimization must before connect at server side*/
    if(EC_FALSE == csocket_unix_optimize(sockfd))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_connect: sockfd %d failed in some optimization\n", sockfd);
    }

    /* connect to server, connect timeout is default 75s */
    if(0 > connect(sockfd, (struct sockaddr *) &srv_addr, srv_addr_len) /*&& EINPROGRESS != errno && EINTR != errno*/)
    {
        int errcode;

        errcode = errno;

        switch(errcode)
        {
            case EACCES:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, write permission is denied on the socket file, or search permission is denied for one of the directories in the path prefix\n", sockfd);
                break;

            case EPERM:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, tried to connect to a broadcast address without having the socket broadcast flag enabled or the connection request failed because of a local firewall rule\n", sockfd);
                break;

            case EADDRINUSE:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, local address is already in use\n", sockfd);
                break;

            case EAFNOSUPPORT:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, The passed address not have the correct address family in its sa_family fiel\n", sockfd);
                break;

            case EADDRNOTAVAIL:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, non-existent interface was requested or the requested address was not local\n", sockfd);
                break;

            case EALREADY:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, the socket is non-blocking and a previous connection attempt has not yet been completed\n", sockfd);
                break;

            case EBADF:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, the file descriptor is not a valid index in the descriptor tabl\n", sockfd);
                break;

            case ECONNREFUSED:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, no one listening on remote %s:%ld\n", sockfd, c_word_to_ipv4(srv_ipaddr), srv_port);
                break;

            case EFAULT:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, the socket structure address is outside the user address space\n", sockfd);
                break;

            case EINPROGRESS:
                dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT, "warn:csocket_unix_connect: sockfd %d is in progress\n", sockfd);
                if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode)
                {
                    csocket_nonblock_enable(sockfd);
                }
                *client_sockfd = sockfd;
                return ( EC_TRUE );

            case EINTR:
                dbg_log(SEC_0053_CSOCKET, 1)(LOGSTDOUT, "warn:csocket_unix_connect: sockfd %d, the system call was interrupted by a signal that was caugh\n", sockfd);
                if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode)
                {
                    csocket_nonblock_enable(sockfd);
                }
                *client_sockfd = sockfd;
                return ( EC_TRUE );

            case EISCONN:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d is already connected\n", sockfd);
                break;

            case ENETUNREACH:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, network is unreachabl\n", sockfd);
                break;

            case ENOTSOCK:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, the file descriptor is not associated with a socket\n", sockfd);
                break;

            case ETIMEDOUT:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, timeout while attempting connection. The server may be too busy to accept new connection\n", sockfd);
                break;

            case EHOSTDOWN:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, host down\n", sockfd);
                break;

            case EHOSTUNREACH:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, No route to host\n", sockfd);
                break;

            default:
                dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDOUT, "error:csocket_unix_connect: sockfd %d, unknown errno = %d\n", sockfd, errcode);
        }

        /*os error checking by shell command: perror <errno>*/
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR,"error:csocket_unix_connect: sockfd %d connect error, errno = %d, errstr = %s\n", sockfd, errcode, strerror(errcode));

        close(sockfd);
        return ( EC_FALSE );
    }

    *client_sockfd = sockfd;
    return ( EC_TRUE );
}

EC_BOOL csocket_unix_accept(const int srv_sockfd, int *conn_sockfd, const UINT32 csocket_block_mode)
{
    int new_sockfd;

    new_sockfd = accept(srv_sockfd, NULL_PTR, NULL_PTR);
    if( 0 > new_sockfd)
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == csocket_unix_optimize(new_sockfd))
    {
        dbg_log(SEC_0053_CSOCKET, 0)(LOGSTDERR, "warn:csocket_unix_accept: optimize sockfd %d failed\n", new_sockfd);
    }

    if(CSOCKET_IS_BLOCK_MODE == csocket_block_mode)
    {
        csocket_nonblock_disable(new_sockfd);
    }

    (*conn_sockfd) = new_sockfd;

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

