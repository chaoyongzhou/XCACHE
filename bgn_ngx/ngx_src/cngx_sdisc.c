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

#if (SWITCH_ON == NGX_BGN_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"
#include "cmisc.h"

#include "cmpic.inc"
#include "findex.inc"

#include "task.h"

#include "cmon.h"
#include "csdisc.h"
#include "cngx_sdisc.h"

static EC_BOOL cngx_sdisc_sender(void *UNUSED(cycle), CSDISC_NODE *csdisc_node)
{
    static uint64_t     seq_no = 0;
    TASKS_CFG          *tasks_cfg;
    char                buff[ 128 ];
    uint32_t            len;

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());

    /* seq_no, ngx, tcid, ipv4, port
    *
    * jason: {"service":"ngx","tcid":"10.10.67.18","ipv4":"127.0.0.1", "bgn":"618"}
    * string: ngx|<tcid>|<ipv4>|<bgn port>
    *
    */
    len = snprintf(buff, sizeof(buff)/sizeof(buff[0]),
                         "{%ld|ngx|%s|%s|%ld}",
                         seq_no,
                         c_word_to_ipv4(CMPI_LOCAL_TCID),
                         c_word_to_ipv4(TASKS_CFG_SRVIPADDR(tasks_cfg)),
                         TASKS_CFG_SRVPORT(tasks_cfg));

    if(EC_FALSE == csdisc_node_send_packet(csdisc_node, (const uint8_t *)buff, len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_sdisc_sender: "
                                             "send '%.*s' failed\n",
                                             len, (char *)buff);
        return (EC_FALSE);
    }

    seq_no ++;

    dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "[DEBUG] cngx_sdisc_sender: "
                                         "send '%.*s' done\n",
                                         len, (char *)buff);
    return (EC_TRUE);
}

static EC_BOOL cngx_sdisc_recver(void *UNUSED(cycle), CSDISC_NODE *csdisc_node)
{
    static char  buff[ 1024 ];

    char        *s_buff;
    char        *e_buff;
    char        *c_buff;
    uint32_t     len;
    uint32_t     segs_num;
    char        *segs[ 8 ];
    char        *seg;
    UINT32       xfs_tcid;
    UINT32       xfs_modi;
    UINT32       xfs_ipv4;
    UINT32       xfs_bgn_port;

    MOD_NODE     recv_mod_node;
    CMON_NODE    cmon_node;

    if(EC_FALSE == csdisc_node_recv_packet(csdisc_node, (uint8_t *)buff,
                            sizeof(buff)/sizeof(buff[0]), &len))
    {
        return (EC_FALSE);
    }

    if(0 == len)
    {
        return (EC_TRUE);
    }

    s_buff = (char *)buff;
    e_buff = s_buff + len;

    while(s_buff < e_buff)
    {
        while('{' != *s_buff && s_buff < e_buff)
        {
            s_buff ++;
        }

        if(s_buff >= e_buff)
        {
            return (EC_TRUE);
        }

        c_buff = s_buff + 1;
        while('}' != *c_buff && c_buff < e_buff)
        {
            c_buff ++;
        }

        if(c_buff >= e_buff)
        {
            return (EC_TRUE);
        }

        dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "[DEBUG] cngx_sdisc_recver: "
                                             "recv '%.*s' done\n",
                                             c_buff - s_buff + 1, (char *)s_buff);

        s_buff ++;
        *c_buff = '\0';

        segs_num = c_str_split((char *)s_buff, (const char *)"|",
                                (char **)segs, sizeof(segs)/sizeof(segs[0]));

        s_buff = c_buff + 1; /*update*/

        /* seq_no, xfs, tcid, ipv4, port, modi
        *
        * jason: {"service":"xfs","tcid":"10.10.67.18","ipv4":"127.0.0.1", "bgn":"618", "modi":"0"}
        * string: xfs|<tcid>|<ipv4>|<bgn port>|<xfs modi>
        *
        */

        if(6 != segs_num)
        {
            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_sdisc_recver: "
                                                 "recv segs num %u is invalid => ignore\n",
                                                 segs_num);
            continue;
        }

         /*skip seq_no*/

        seg = segs[1];
        if(0 != STRCASECMP(seg, "xfs"))
        {
            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_sdisc_recver: "
                                                 "recv '%s' is not xfs => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[2];
        xfs_tcid = c_ipv4_to_word(seg);
        if(0 == xfs_tcid)
        {
            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_sdisc_recver: "
                                                 "recv '%s' invalid tcid => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[3];
        xfs_ipv4 = c_ipv4_to_word(seg);
        if(0 == xfs_ipv4)
        {
            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_sdisc_recver: "
                                                 "recv '%s' invalid ipv4 => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[4];
        xfs_bgn_port = c_str_to_word(seg);
        if(0 != (xfs_bgn_port & ~(0xFFFF)))
        {
            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_sdisc_recver: "
                                                 "recv '%s' invalid bgn port => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[5];
        xfs_modi = c_str_to_word(segs[5]);

        /*connect ngx if necessary*/

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &recv_mod_node,
                         NULL_PTR,
                         FI_super_add_connection, CMPI_ERROR_MODI, xfs_tcid, CMPI_ANY_COMM, xfs_ipv4, xfs_bgn_port,
                         (UINT32)CSOCKET_CNODE_NUM);

        /*add cxfs node to NGX BGN*/
        cmon_node_init(&cmon_node);
        CMON_NODE_TCID(&cmon_node)  = xfs_tcid;
        CMON_NODE_MODI(&cmon_node)  = xfs_modi;
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;

        cmon_add_node(task_brd_default_get_cmon_id(), &cmon_node);
        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_sdisc_push_sender(void *cycle)
{
    CSDISC_NODE *csdisc_node;

    csdisc_node = task_brd_default_get_sdisc_running();

    return csdisc_node_push_sender(csdisc_node, (CSDISC_SENDER_FUNC)cngx_sdisc_sender, (void *)cycle);
}

EC_BOOL cngx_sdisc_push_recver(void *cycle)
{
    CSDISC_NODE *csdisc_node;

    csdisc_node = task_brd_default_get_sdisc_running();

    return csdisc_node_push_recver(csdisc_node, (CSDISC_SENDER_FUNC)cngx_sdisc_recver, (void *)cycle);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
