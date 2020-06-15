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
#include "mm.h"
#include "log.h"

#include "cmisc.h"
#include "cmpic.inc"

#include "cparacfg.inc"
#include "cparacfg.h"

#include "json.h"

CPARACFG *cparacfg_new(const UINT32 this_tcid, const UINT32 this_rank)
{
    CPARACFG *cparacfg;
    alloc_static_mem(MM_CPARACFG, &cparacfg, LOC_CPARACFG_0001);
    if(NULL_PTR != cparacfg)
    {
        cparacfg_init(cparacfg, this_tcid, this_rank);
    }
    return (cparacfg);
}

EC_BOOL cparacfg_clean(CPARACFG *cparacfg)
{
    return (EC_TRUE);
}

EC_BOOL cparacfg_free(CPARACFG *cparacfg)
{
    if(NULL_PTR != cparacfg)
    {
        cparacfg_clean(cparacfg);
        free_static_mem(MM_CPARACFG, cparacfg, LOC_CPARACFG_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cparacfg_init(CPARACFG *cparacfg, const UINT32 this_tcid, const UINT32 this_rank)
{
    CPARACFG_TCID(cparacfg) = this_tcid;
    CPARACFG_RANK(cparacfg) = this_rank;

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_PROC_CORE_ID);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_REQ_THREAD_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_RSP_THREAD_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CTHREAD_STACK_MAX_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CTHREAD_STACK_GUARD_SIZE);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_SLOW_DOWN_MSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_SNDBUFF_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_RCVBUFF_SIZE);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_CNODE_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_FILE_LOG_MAX_RECORDS);

    //CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CONN_KEEPALIVE_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CONN_TIMEOUT_NSEC);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDNS_TIMEOUT_NSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_DNS_CACHE_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_DNS_CACHE_EXPIRED_NSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_HIGH_PRECISION_TIME_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_BGN_OVER_RFS_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_BGN_OVER_XFS_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSNP_CACHE_IN_MEM_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSDN_CACHE_IN_MEM_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSDN_CAMD_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSDN_CAMD_SATA_DISK_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSDN_CAMD_MEM_DISK_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSDN_CAMD_SSD_DISK_OFFSET);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSDN_CAMD_SSD_DISK_SIZE);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSNP_MAX_USED_RATIO);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_MAX_USED_RATIO);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_CAMD_SWITCH);
    //CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_CAMD_SATA_DISK_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_CAMD_SSD_DISK_OFFSET);
    //CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFSDN_CAMD_SSD_DISK_SIZE);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFS_LRU_MODEL_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CXFS_FIFO_MODEL_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMON_CONHASH_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMON_CONHASH_REPLICAS);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMON_HOT_PATH_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_EPOLL_TIMEOUT_MSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP);

    CPARACFG_SET_STR_DEFAULT(cparacfg, CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR);
    CPARACFG_SET_STR_DEFAULT(cparacfg, CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TDNS_RESOLVE_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CAMD_SATA_DISK_VM_S_OFFSET);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_TRY_RETIRE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_TRY_RECYCLE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_SCAN_RETIRE_MAX_NUM);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_FLOW_CONTROL_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_DEGRADE_HI_RATIO);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_DEGRADE_MD_RATIO);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_DEGRADE_LO_RATIO);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_LRU_MODEL_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CMC_FIFO_MODEL_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_TRY_RETIRE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_TRY_RECYCLE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_SCAN_RETIRE_MAX_NUM);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_READ_CACHE_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_FLOW_CONTROL_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_DEGRADE_HI_RATIO);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_DEGRADE_MD_RATIO);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_DEGRADE_LO_RATIO);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_LRU_MODEL_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CDC_FIFO_MODEL_SWITCH);

    log_level_tab_init(CPARACFG_LOG_LEVEL_TAB(cparacfg), SEC_NONE_END, LOG_DEFAULT_DBG_LEVEL);

    return (EC_TRUE);
}

EC_BOOL cparacfg_clone(const CPARACFG *cparacfg_src, CPARACFG *cparacfg_des)
{
    BCOPY(cparacfg_src, cparacfg_des, sizeof(CPARACFG));
    return (EC_TRUE);
}

EC_BOOL cparacfg_validity_check(const CPARACFG *cparacfg)
{
    EC_BOOL ret;

    ret = EC_TRUE;

    if(2 > CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg))
    {
        dbg_log(SEC_0052_CPARACFG, 0)(LOGSTDOUT, "error:cparacfg_check: TASK_REQ_THREAD_MAX_NUM is less than 2\n");
        ret = EC_FALSE;
    }

    return (ret);
}

EC_BOOL cparacfg_cmp(const CPARACFG *cparacfg_1st, const CPARACFG *cparacfg_2nd)
{
    if(CPARACFG_TCID(cparacfg_1st) != CPARACFG_TCID(cparacfg_2nd) )
    {
        return (EC_FALSE);
    }

    if(CPARACFG_RANK(cparacfg_1st) != CPARACFG_RANK(cparacfg_2nd) )
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cparacfg_print(LOG *log, const CPARACFG *cparacfg)
{
    sys_log(log, "tcid = %s, rank = %ld\n",  CPARACFG_TCID_STR(cparacfg), CPARACFG_RANK(cparacfg));

    sys_log(log, "TASK_REQ_THREAD_MAX_NUM                    = %ld\n",  CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg)       );
    sys_log(log, "TASK_RSP_THREAD_MAX_NUM                    = %ld\n",  CPARACFG_TASK_RSP_THREAD_MAX_NUM(cparacfg)       );
    sys_log(log, "CTHREAD_STACK_MAX_SIZE                     = %ld\n",  CPARACFG_CTHREAD_STACK_MAX_SIZE(cparacfg)        );
    sys_log(log, "CTHREAD_STACK_GUARD_SIZE                   = %ld\n",  CPARACFG_CTHREAD_STACK_GUARD_SIZE(cparacfg)      );

    sys_log(log, "CPARACFG_TASK_SLOW_DOWN_MSEC               = %ld\n",  CPARACFG_TASK_SLOW_DOWN_MSEC(cparacfg)           );

    sys_log(log, "CSOCKET_SO_SNDBUFF_SIZE                    = %d\n",   CPARACFG_CSOCKET_SO_SNDBUFF_SIZE(cparacfg)        );
    sys_log(log, "CSOCKET_SO_RCVBUFF_SIZE                    = %d\n",   CPARACFG_CSOCKET_SO_RCVBUFF_SIZE(cparacfg)        );

    sys_log(log, "CSOCKET_SO_SNDLOWAT_SIZE                   = %d\n",   CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE(cparacfg)        );
    sys_log(log, "CSOCKET_SO_RCVLOWAT_SIZE                   = %d\n",   CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE(cparacfg)        );


    sys_log(log, "CSOCKET_SO_SNDTIMEO_NSEC                   = %d\n",   CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC(cparacfg)        );
    sys_log(log, "CSOCKET_SO_RCVTIMEO_NSEC                   = %d\n",   CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC(cparacfg)        );

    sys_log(log, "CSOCKET_SO_KEEPALIVE_SWITCH                = %s\n",   CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH_STR(cparacfg) );
    sys_log(log, "CSOCKET_TCP_KEEPIDLE_NSEC                  = %d\n",   CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC(cparacfg)       );
    sys_log(log, "CSOCKET_TCP_KEEPINTVL_NSEC                 = %d\n",   CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC(cparacfg)      );
    sys_log(log, "CSOCKET_TCP_KEEPCNT_TIMES                  = %d\n",   CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES(cparacfg)       );

    sys_log(log, "CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE        = %ld\n",  CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE(cparacfg)      );
    sys_log(log, "CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE        = %ld\n",  CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE(cparacfg)      );
    sys_log(log, "CSOCKET_CNODE_NUM                          = %ld\n",  CPARACFG_CSOCKET_CNODE_NUM(cparacfg)             );
    sys_log(log, "CSOCKET_HEARTBEAT_INTVL_NSEC               = %ld\n",  CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC(cparacfg)  );
    sys_log(log, "FILE_LOG_MAX_RECORDS                       = %ld\n",  CPARACFG_FILE_LOG_MAX_RECORDS(cparacfg)          );

    //sys_log(log, "CPARACFG_CONN_KEEPALIVE_SWITCH             = %s\n" ,  CPARACFG_CONN_KEEPALIVE_SWITCH_STR(cparacfg));
    sys_log(log, "CONN_TIMEOUT_NSEC                          = %ld\n",  CPARACFG_CONN_TIMEOUT_NSEC(cparacfg));
    sys_log(log, "TIMEOUT_MAX_NUM_PER_LOOP                   = %ld\n",  CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg));
    sys_log(log, "CDNS_TIMEOUT_NSEC                          = %ld\n",  CPARACFG_CDNS_TIMEOUT_NSEC(cparacfg));

    sys_log(log, "DNS_CACHE_SWITCH                           = %s\n" ,  CPARACFG_DNS_CACHE_SWITCH_STR(cparacfg));
    sys_log(log, "DNS_CACHE_EXPIRED_NSEC                     = %ld\n",  CPARACFG_DNS_CACHE_EXPIRED_NSEC(cparacfg));

    sys_log(log, "HIGH_PRECISION_TIME_SWITCH                 = %s\n" ,  CPARACFG_HIGH_PRECISION_TIME_SWITCH_STR(cparacfg));
    sys_log(log, "NGX_BGN_OVER_RFS_SWITCH                    = %s\n" ,  CPARACFG_NGX_BGN_OVER_RFS_SWITCH_STR(cparacfg));
    sys_log(log, "NGX_BGN_OVER_XFS_SWITCH                    = %s\n" ,  CPARACFG_NGX_BGN_OVER_XFS_SWITCH_STR(cparacfg));

    sys_log(log, "CRFSNP_TRY_RETIRE_MAX_NUM                  = %ld\n",  CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM(cparacfg));
    sys_log(log, "CRFSNP_TRY_RECYCLE_MAX_NUM                 = %ld\n",  CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM(cparacfg));
    sys_log(log, "CRFSNP_CACHE_IN_MEM_SWITCH                 = %s\n" ,  CPARACFG_CRFSNP_CACHE_IN_MEM_SWITCH_STR(cparacfg));
    sys_log(log, "CRFSDN_CACHE_IN_MEM_SWITCH                 = %s\n" ,  CPARACFG_CRFSDN_CACHE_IN_MEM_SWITCH_STR(cparacfg));

    sys_log(log, "CRFSDN_CAMD_SWITCH                         = %s\n" ,  CPARACFG_CRFSDN_CAMD_SWITCH_STR(cparacfg));
    sys_log(log, "CRFSDN_CAMD_SATA_DISK_SIZE                 = %ld\n",  CPARACFG_CRFSDN_CAMD_SATA_DISK_SIZE(cparacfg));
    sys_log(log, "CRFSDN_CAMD_MEM_DISK_SIZE                  = %ld\n",  CPARACFG_CRFSDN_CAMD_MEM_DISK_SIZE(cparacfg));
    sys_log(log, "CRFSDN_CAMD_SSD_DISK_OFFSET                = %ld\n",  CPARACFG_CRFSDN_CAMD_SSD_DISK_OFFSET(cparacfg));
    sys_log(log, "CRFSDN_CAMD_SSD_DISK_SIZE                  = %ld\n",  CPARACFG_CRFSDN_CAMD_SSD_DISK_SIZE(cparacfg));

    sys_log(log, "CXFSNP_MAX_USED_RATIO                      = %.3f\n",  CPARACFG_CXFSNP_MAX_USED_RATIO(cparacfg));
    sys_log(log, "CXFSDN_MAX_USED_RATIO                      = %.3f\n",  CPARACFG_CXFSDN_MAX_USED_RATIO(cparacfg));

    sys_log(log, "CXFSNP_TRY_RETIRE_MAX_NUM                  = %ld\n",  CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM(cparacfg));
    sys_log(log, "CXFSNP_TRY_RECYCLE_MAX_NUM                 = %ld\n",  CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM(cparacfg));
    sys_log(log, "CXFSNP_CACHE_IN_MEM_SWITCH                 = %s\n" ,  CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH_STR(cparacfg));
    sys_log(log, "CXFSDN_CACHE_IN_MEM_SWITCH                 = %s\n" ,  CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH_STR(cparacfg));

    sys_log(log, "CXFSDN_CAMD_SWITCH                         = %s\n" ,  CPARACFG_CXFSDN_CAMD_SWITCH_STR(cparacfg));
    //sys_log(log, "CXFSDN_CAMD_SATA_DISK_SIZE        = %ld\n",  CPARACFG_CXFSDN_CAMD_SATA_DISK_SIZE(cparacfg));
    sys_log(log, "CXFSDN_CAMD_MEM_DISK_SIZE                  = %ld\n",  CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE(cparacfg));
    sys_log(log, "CXFSDN_CAMD_SSD_DISK_OFFSET                = %ld\n",  CPARACFG_CXFSDN_CAMD_SSD_DISK_OFFSET(cparacfg));
    //sys_log(log, "CXFSDN_CAMD_SSD_DISK_SIZE         = %ld\n",  CPARACFG_CXFSDN_CAMD_SSD_DISK_SIZE(cparacfg));

    sys_log(log, "CXFS_LRU_MODEL_SWITCH                      = %s\n",   CPARACFG_CXFS_LRU_MODEL_SWITCH_STR(cparacfg));
    sys_log(log, "CXFS_FIFO_MODEL_SWITCH                     = %s\n",   CPARACFG_CXFS_FIFO_MODEL_SWITCH_STR(cparacfg));

    sys_log(log, "CAMD_SATA_DISK_VM_S_OFFSET                 = %ld\n" ,  CPARACFG_CAMD_SATA_DISK_VM_S_OFFSET(cparacfg));
    sys_log(log, "CMON_CONHASH_SWITCH                        = %s\n" ,  CPARACFG_CMON_CONHASH_SWITCH_STR(cparacfg));
    sys_log(log, "CMON_CONHASH_REPLICAS                      = %u\n" ,  CPARACFG_CMON_CONHASH_REPLICAS(cparacfg));
    sys_log(log, "CMON_HOT_PATH_SWITCH                       = %s\n" ,  CPARACFG_CMON_HOT_PATH_SWITCH_STR(cparacfg));

    sys_log(log, "NGX_LUA_OUTPUT_BLOCKING_LOWAT              = %u\n" ,  CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg));
    sys_log(log, "NGX_EPOLL_TIMEOUT_MSEC                     = %u\n" ,  CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg));

    sys_log(log, "NGX_HTTP_REQ_NUM_PER_LOOP                  = %u\n" ,  CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    sys_log(log, "RFS_HTTP_REQ_NUM_PER_LOOP                  = %u\n" ,  CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    sys_log(log, "XFS_HTTP_REQ_NUM_PER_LOOP                  = %u\n" ,  CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));

    sys_log(log, "CAMD_SSD_AIO_REQ_MAX_NUM                   = %ld\n" , CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM(cparacfg));
    sys_log(log, "CAMD_SATA_AIO_REQ_MAX_NUM                  = %ld\n" , CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM(cparacfg));
    sys_log(log, "CAMD_SATA_DEGRADE_SSD_SWITCH               = %s\n"  , CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH_STR(cparacfg));

    sys_log(log, "CAMD_SSD_UPGRADE_MEM_SWITCH                = %s\n"  ,  CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH_STR(cparacfg));
    sys_log(log, "CAMD_SATA_UPGRADE_MEM_SWITCH               = %s\n"  ,  CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH_STR(cparacfg));

    sys_log(log, "CMC_TRY_RETIRE_MAX_NUM_NUM                 = %ld\n" , CPARACFG_CMC_TRY_RETIRE_MAX_NUM(cparacfg));
    sys_log(log, "CMC_TRY_RECYCLE_MAX_NUM                    = %ld\n" , CPARACFG_CMC_TRY_RECYCLE_MAX_NUM(cparacfg));
    sys_log(log, "CMC_SCAN_RETIRE_MAX_NUM                    = %ld\n" , CPARACFG_CMC_SCAN_RETIRE_MAX_NUM(cparacfg));

    sys_log(log, "CMC_FLOW_CONTROL_SWITCH                    = %s\n" , CPARACFG_CMC_FLOW_CONTROL_SWITCH_STR(cparacfg));
    sys_log(log, "CMC_PROCESS_DEGRADE_MAX_NUM                = %ld\n" , CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM(cparacfg));
    sys_log(log, "CMC_SCAN_DEGRADE_MAX_NUM                   = %ld\n" , CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM(cparacfg));

    sys_log(log, "CMC_DEGRADE_HI_RATIO                       = %.2f\n", CPARACFG_CMC_DEGRADE_HI_RATIO(cparacfg));
    sys_log(log, "CMC_DEGRADE_MD_RATIO                       = %.2f\n", CPARACFG_CMC_DEGRADE_MD_RATIO(cparacfg));
    sys_log(log, "CMC_DEGRADE_LO_RATIO                       = %.2f\n", CPARACFG_CMC_DEGRADE_LO_RATIO(cparacfg));

    sys_log(log, "CMC_LRU_MODEL_SWITCH                       = %s\n",   CPARACFG_CMC_LRU_MODEL_SWITCH_STR(cparacfg));
    sys_log(log, "CMC_FIFO_MODEL_SWITCH                      = %s\n",   CPARACFG_CMC_FIFO_MODEL_SWITCH_STR(cparacfg));

    sys_log(log, "CDC_TRY_RETIRE_MAX_NUM_NUM                 = %ld\n" , CPARACFG_CDC_TRY_RETIRE_MAX_NUM(cparacfg));
    sys_log(log, "CDC_TRY_RECYCLE_MAX_NUM                    = %ld\n" , CPARACFG_CDC_TRY_RECYCLE_MAX_NUM(cparacfg));
    sys_log(log, "CDC_SCAN_RETIRE_MAX_NUM                    = %ld\n" , CPARACFG_CDC_SCAN_RETIRE_MAX_NUM(cparacfg));

    sys_log(log, "CDC_READ_CACHE_SWITCH                      = %s\n"  , CPARACFG_CDC_READ_CACHE_SWITCH_STR(cparacfg));
    sys_log(log, "CDC_FLOW_CONTROL_SWITCH                    = %s\n"  , CPARACFG_CDC_FLOW_CONTROL_SWITCH_STR(cparacfg));
    sys_log(log, "CDC_PROCESS_DEGRADE_MAX_NUM                = %ld\n" , CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM(cparacfg));
    sys_log(log, "CDC_SCAN_DEGRADE_MAX_NUM                   = %ld\n" , CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM(cparacfg));

    sys_log(log, "CDC_DEGRADE_HI_RATIO                       = %.2f\n", CPARACFG_CDC_DEGRADE_HI_RATIO(cparacfg));
    sys_log(log, "CDC_DEGRADE_MD_RATIO                       = %.2f\n", CPARACFG_CDC_DEGRADE_MD_RATIO(cparacfg));
    sys_log(log, "CDC_DEGRADE_LO_RATIO                       = %.2f\n", CPARACFG_CDC_DEGRADE_LO_RATIO(cparacfg));

    sys_log(log, "CDC_LRU_MODEL_SWITCH                       = %s\n",   CPARACFG_CDC_LRU_MODEL_SWITCH_STR(cparacfg));
    sys_log(log, "CDC_FIFO_MODEL_SWITCH                      = %s\n",   CPARACFG_CDC_FIFO_MODEL_SWITCH_STR(cparacfg));

    return;
}

void cparacfg_json(json_object *obj, const CPARACFG *cparacfg)
{
    json_object_add_kv(obj,      "tcid", CPARACFG_TCID_STR(cparacfg));
    json_object_add_k_int64(obj, "rank", CPARACFG_RANK(cparacfg));

    json_object_add_k_int64(obj, "TASK_REQ_THREAD_MAX_NUM" ,  CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "TASK_RSP_THREAD_MAX_NUM" ,  CPARACFG_TASK_RSP_THREAD_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CTHREAD_STACK_MAX_SIZE"  ,  CPARACFG_CTHREAD_STACK_MAX_SIZE(cparacfg));
    json_object_add_k_int64(obj, "CTHREAD_STACK_GUARD_SIZE",  CPARACFG_CTHREAD_STACK_GUARD_SIZE(cparacfg));

    json_object_add_k_int64(obj, "TASK_SLOW_DOWN_MSEC",  CPARACFG_TASK_SLOW_DOWN_MSEC(cparacfg));

    json_object_add_k_int32(obj, "CSOCKET_SO_SNDBUFF_SIZE",   CPARACFG_CSOCKET_SO_SNDBUFF_SIZE(cparacfg));
    json_object_add_k_int32(obj, "CSOCKET_SO_RCVBUFF_SIZE",   CPARACFG_CSOCKET_SO_RCVBUFF_SIZE(cparacfg));

    json_object_add_k_int32(obj, "CSOCKET_SO_SNDLOWAT_SIZE",   CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE(cparacfg));
    json_object_add_k_int32(obj, "CSOCKET_SO_RCVLOWAT_SIZE",   CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE(cparacfg));


    json_object_add_k_int32(obj, "CSOCKET_SO_SNDTIMEO_NSEC",   CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC(cparacfg));
    json_object_add_k_int32(obj, "CSOCKET_SO_RCVTIMEO_NSEC",   CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC(cparacfg));

    json_object_add_kv(obj,      "CSOCKET_SO_KEEPALIVE_SWITCH", CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH_STR(cparacfg));
    json_object_add_k_int32(obj, "CSOCKET_TCP_KEEPIDLE_NSEC"  , CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC(cparacfg));
    json_object_add_k_int32(obj, "CSOCKET_TCP_KEEPINTVL_NSEC" , CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC(cparacfg));
    json_object_add_k_int32(obj, "CSOCKET_TCP_KEEPCNT_TIMES"  , CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES(cparacfg));

    json_object_add_k_int64(obj, "CSOCKET_SEND_ONCE_MAX_SIZE"  ,  CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE(cparacfg));
    json_object_add_k_int64(obj, "CSOCKET_RECV_ONCE_MAX_SIZE"  ,  CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE(cparacfg));
    json_object_add_k_int64(obj, "CSOCKET_CNODE_NUM"           ,  CPARACFG_CSOCKET_CNODE_NUM(cparacfg));
    json_object_add_k_int64(obj, "CSOCKET_HEARTBEAT_INTVL_NSEC",  CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC(cparacfg));
    json_object_add_k_int64(obj, "FILE_LOG_MAX_RECORDS"        ,  CPARACFG_FILE_LOG_MAX_RECORDS(cparacfg));

    json_object_add_k_int64(obj, "CONN_TIMEOUT_NSEC"       ,  CPARACFG_CONN_TIMEOUT_NSEC(cparacfg));
    json_object_add_k_int64(obj, "TIMEOUT_MAX_NUM_PER_LOOP",  CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg));
    json_object_add_k_int64(obj, "CDNS_TIMEOUT_NSEC"       ,  CPARACFG_CDNS_TIMEOUT_NSEC(cparacfg));

    json_object_add_kv(obj,      "DNS_CACHE_SWITCH"        ,  CPARACFG_DNS_CACHE_SWITCH_STR(cparacfg));
    json_object_add_k_int64(obj, "DNS_CACHE_EXPIRED_NSEC"  ,  CPARACFG_DNS_CACHE_EXPIRED_NSEC(cparacfg));

    json_object_add_kv(obj, "HIGH_PRECISION_TIME_SWITCH"   ,  CPARACFG_HIGH_PRECISION_TIME_SWITCH_STR(cparacfg));
    json_object_add_kv(obj, "NGX_BGN_OVER_RFS_SWITCH"      ,  CPARACFG_NGX_BGN_OVER_RFS_SWITCH_STR(cparacfg));
    json_object_add_kv(obj, "NGX_BGN_OVER_XFS_SWITCH"      ,  CPARACFG_NGX_BGN_OVER_XFS_SWITCH_STR(cparacfg));

    json_object_add_k_int64(obj, "CRFSNP_TRY_RETIRE_MAX_NUM"  ,  CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CRFSNP_TRY_RECYCLE_MAX_NUM" ,  CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM(cparacfg));
    json_object_add_kv(obj,      "CRFSNP_CACHE_IN_MEM_SWITCH" ,  CPARACFG_CRFSNP_CACHE_IN_MEM_SWITCH_STR(cparacfg));
    json_object_add_kv(obj,      "CRFSDN_CACHE_IN_MEM_SWITCH" ,  CPARACFG_CRFSDN_CACHE_IN_MEM_SWITCH_STR(cparacfg));

    json_object_add_kv(obj,      "CRFSDN_CAMD_SWITCH"         ,  CPARACFG_CRFSDN_CAMD_SWITCH_STR(cparacfg));
    json_object_add_k_int64(obj, "CRFSDN_CAMD_SATA_DISK_SIZE" ,  CPARACFG_CRFSDN_CAMD_SATA_DISK_SIZE(cparacfg));
    json_object_add_k_int64(obj, "CRFSDN_CAMD_MEM_DISK_SIZE"  ,  CPARACFG_CRFSDN_CAMD_MEM_DISK_SIZE(cparacfg));
    json_object_add_k_int64(obj, "CRFSDN_CAMD_SSD_DISK_OFFSET",  CPARACFG_CRFSDN_CAMD_SSD_DISK_OFFSET(cparacfg));
    json_object_add_k_int64(obj, "CRFSDN_CAMD_SSD_DISK_SIZE"  ,  CPARACFG_CRFSDN_CAMD_SSD_DISK_SIZE(cparacfg));

    json_object_add_k_double(obj, "CXFSNP_MAX_USED_RATIO",  CPARACFG_CXFSNP_MAX_USED_RATIO(cparacfg));
    json_object_add_k_double(obj, "CXFSDN_MAX_USED_RATIO",  CPARACFG_CXFSDN_MAX_USED_RATIO(cparacfg));

    json_object_add_k_int64(obj, "CXFSNP_TRY_RETIRE_MAX_NUM" ,  CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CXFSNP_TRY_RECYCLE_MAX_NUM",  CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM(cparacfg));
    json_object_add_kv(obj,      "CXFSNP_CACHE_IN_MEM_SWITCH",  CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH_STR(cparacfg));
    json_object_add_kv(obj,      "CXFSDN_CACHE_IN_MEM_SWITCH",  CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH_STR(cparacfg));

    json_object_add_kv(obj,      "CXFSDN_CAMD_SWITCH"         ,  CPARACFG_CXFSDN_CAMD_SWITCH_STR(cparacfg));
    json_object_add_k_int64(obj, "CXFSDN_CAMD_MEM_DISK_SIZE"  ,  CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE(cparacfg));
    json_object_add_k_int64(obj, "CXFSDN_CAMD_SSD_DISK_OFFSET",  CPARACFG_CXFSDN_CAMD_SSD_DISK_OFFSET(cparacfg));
    json_object_add_k_int64(obj, "CAMD_SATA_DISK_VM_S_OFFSET" ,  CPARACFG_CAMD_SATA_DISK_VM_S_OFFSET(cparacfg));

    json_object_add_kv(obj,      "CXFS_LRU_MODEL_SWITCH"      , CPARACFG_CXFS_LRU_MODEL_SWITCH_STR(cparacfg));
    json_object_add_kv(obj,      "CXFS_FIFO_MODEL_SWITCH"     , CPARACFG_CXFS_FIFO_MODEL_SWITCH_STR(cparacfg));

    json_object_add_kv(obj,      "CMON_CONHASH_SWITCH"        ,  CPARACFG_CMON_CONHASH_SWITCH_STR(cparacfg));
    json_object_add_k_int32(obj, "CMON_CONHASH_REPLICAS"      ,  CPARACFG_CMON_CONHASH_REPLICAS(cparacfg));
    json_object_add_kv(obj,      "CMON_HOT_PATH_SWITCH"       ,  CPARACFG_CMON_HOT_PATH_SWITCH_STR(cparacfg));

    json_object_add_k_int32(obj, "NGX_LUA_OUTPUT_BLOCKING_LOWAT",  CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg));
    json_object_add_k_int32(obj, "NGX_EPOLL_TIMEOUT_MSEC"       ,  CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg));

    json_object_add_k_int32(obj, "NGX_HTTP_REQ_NUM_PER_LOOP",  CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    json_object_add_k_int32(obj, "RFS_HTTP_REQ_NUM_PER_LOOP",  CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    json_object_add_k_int32(obj, "XFS_HTTP_REQ_NUM_PER_LOOP",  CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));

    json_object_add_k_int64(obj, "CAMD_SSD_AIO_REQ_MAX_NUM"    , CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CAMD_SATA_AIO_REQ_MAX_NUM"   , CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM(cparacfg));
    json_object_add_kv(obj,      "CAMD_SATA_DEGRADE_SSD_SWITCH", CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH_STR(cparacfg));

    json_object_add_kv(obj, "CAMD_SSD_UPGRADE_MEM_SWITCH"  ,  CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH_STR(cparacfg));
    json_object_add_kv(obj, "CAMD_SATA_UPGRADE_MEM_SWITCH" ,  CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH_STR(cparacfg));

    json_object_add_k_int64(obj, "CMC_TRY_RETIRE_MAX_NUM_NUM", CPARACFG_CMC_TRY_RETIRE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CMC_TRY_RECYCLE_MAX_NUM"   , CPARACFG_CMC_TRY_RECYCLE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CMC_SCAN_RETIRE_MAX_NUM"   , CPARACFG_CMC_SCAN_RETIRE_MAX_NUM(cparacfg));

    json_object_add_kv(obj,      "CMC_FLOW_CONTROL_SWITCH"    , CPARACFG_CMC_FLOW_CONTROL_SWITCH_STR(cparacfg));
    json_object_add_k_int64(obj, "CMC_PROCESS_DEGRADE_MAX_NUM", CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CMC_SCAN_DEGRADE_MAX_NUM"   , CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM(cparacfg));

    json_object_add_k_double(obj, "CMC_DEGRADE_HI_RATIO", CPARACFG_CMC_DEGRADE_HI_RATIO(cparacfg));
    json_object_add_k_double(obj, "CMC_DEGRADE_MD_RATIO", CPARACFG_CMC_DEGRADE_MD_RATIO(cparacfg));
    json_object_add_k_double(obj, "CMC_DEGRADE_LO_RATIO", CPARACFG_CMC_DEGRADE_LO_RATIO(cparacfg));

    json_object_add_kv(obj,      "CMC_LRU_MODEL_SWITCH"      , CPARACFG_CMC_LRU_MODEL_SWITCH_STR(cparacfg));
    json_object_add_kv(obj,      "CMC_FIFO_MODEL_SWITCH"     , CPARACFG_CMC_FIFO_MODEL_SWITCH_STR(cparacfg));

    json_object_add_k_int64(obj, "CDC_TRY_RETIRE_MAX_NUM_NUM", CPARACFG_CDC_TRY_RETIRE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CDC_TRY_RECYCLE_MAX_NUM"   , CPARACFG_CDC_TRY_RECYCLE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CDC_SCAN_RETIRE_MAX_NUM"   , CPARACFG_CDC_SCAN_RETIRE_MAX_NUM(cparacfg));

    json_object_add_kv(obj,      "CDC_READ_CACHE_SWITCH"      , CPARACFG_CDC_READ_CACHE_SWITCH_STR(cparacfg));
    json_object_add_kv(obj,      "CDC_FLOW_CONTROL_SWITCH"    , CPARACFG_CDC_FLOW_CONTROL_SWITCH_STR(cparacfg));
    json_object_add_k_int64(obj, "CDC_PROCESS_DEGRADE_MAX_NUM", CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM(cparacfg));
    json_object_add_k_int64(obj, "CDC_SCAN_DEGRADE_MAX_NUM"   , CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM(cparacfg));

    json_object_add_k_double(obj, "CDC_DEGRADE_HI_RATIO", CPARACFG_CDC_DEGRADE_HI_RATIO(cparacfg));
    json_object_add_k_double(obj, "CDC_DEGRADE_MD_RATIO", CPARACFG_CDC_DEGRADE_MD_RATIO(cparacfg));
    json_object_add_k_double(obj, "CDC_DEGRADE_LO_RATIO", CPARACFG_CDC_DEGRADE_LO_RATIO(cparacfg));

    json_object_add_kv(obj,      "CDC_LRU_MODEL_SWITCH"      , CPARACFG_CDC_LRU_MODEL_SWITCH_STR(cparacfg));
    json_object_add_kv(obj,      "CDC_FIFO_MODEL_SWITCH"     , CPARACFG_CDC_FIFO_MODEL_SWITCH_STR(cparacfg));

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
