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
#include "crfsnp.h"
#include "chfsnp.inc"
#include "csfsnp.inc"
#include "csfsd.h"

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

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_REQ_THREAD_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_RSP_THREAD_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CTHREAD_STACK_MAX_SIZE);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CTHREAD_STACK_GUARD_SIZE);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_SLOW_DOWN_MSEC);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CBASE64_ENCODE_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TASK_ENCODING_RULE);

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
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH);

    //CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CONN_KEEPALIVE_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CONN_TIMEOUT_NSEC);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_HIGH_PRECISION_TIME_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_BGN_OVER_HTTP_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSMON_CONHASH_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSMON_CONHASH_REPLICAS);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CRFSMON_HOT_PATH_SWITCH);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CHFS_MEMC_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CHFS_MEMC_NP_MODEL);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CHFS_MEMC_BUCKET_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CHFSMON_CONHASH_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CHFSMON_CONHASH_REPLICAS);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSFS_MEMC_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSFS_MEMC_NP_MODEL);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSFS_MEMC_BUCKET_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSFSMON_CONHASH_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_CSFSMON_CONHASH_REPLICAS);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_EPOLL_TIMEOUT_MSEC);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP);

    CPARACFG_SET_STR_DEFAULT(cparacfg, CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR);
    CPARACFG_SET_STR_DEFAULT(cparacfg, CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR);

    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TDNS_RESOLVE_SWITCH);
    CPARACFG_SET_DEFAULT(cparacfg, CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC);

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
    sys_log(log, "CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES      = %ld\n",  CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES(cparacfg)  );

    sys_log(log, "TASK_REQ_HANDLE_THREAD_SWITCH              = %s\n" ,  CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH_STR(cparacfg) );
    sys_log(log, "TASK_REQ_DECODE_THREAD_SWITCH              = %s\n" ,  CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH_STR(cparacfg) );
    sys_log(log, "TASK_RSP_DECODE_THREAD_SWITCH              = %s\n" ,  CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH_STR(cparacfg) );
    sys_log(log, "TASK_FWD_DECODE_THREAD_SWITCH              = %s\n" ,  CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH_STR(cparacfg) );
    sys_log(log, "CBASE64_ENCODE_SWITCH                      = %s\n" ,  CPARACFG_CBASE64_ENCODE_SWITCH_STR(cparacfg)         );
    sys_log(log, "TASK_ENCODING_RULE                         = %ld\n",  CPARACFG_TASK_ENCODING_RULE(cparacfg)            );

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
    sys_log(log, "FILE_LOG_NAME_WITH_DATE_SWITCH             = %s\n" ,  CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH_STR(cparacfg));

    //sys_log(log, "CPARACFG_CONN_KEEPALIVE_SWITCH             = %s\n" ,  CPARACFG_CONN_KEEPALIVE_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_CONN_TIMEOUT_NSEC                 = %ld\n",  CPARACFG_CONN_TIMEOUT_NSEC(cparacfg));
    sys_log(log, "CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP          = %ld\n",  CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg));

    sys_log(log, "CPARACFG_HIGH_PRECISION_TIME_SWITCH        = %s\n" ,  CPARACFG_HIGH_PRECISION_TIME_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_NGX_BGN_OVER_HTTP_SWITCH          = %s\n" ,  CPARACFG_NGX_BGN_OVER_HTTP_SWITCH_STR(cparacfg));

    sys_log(log, "CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM         = %ld\n",  CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM(cparacfg));
    sys_log(log, "CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM        = %s\n" ,  CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM(cparacfg));
    sys_log(log, "CPARACFG_CRFSMON_CONHASH_SWITCH            = %s\n" ,  CPARACFG_CRFSMON_CONHASH_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_CRFSMON_CONHASH_REPLICAS          = %u\n" ,  CPARACFG_CRFSMON_CONHASH_REPLICAS(cparacfg));
    sys_log(log, "CPARACFG_CRFSMON_HOT_PATH_SWITCH           = %s\n" ,  CPARACFG_CRFSMON_HOT_PATH_SWITCH_STR(cparacfg));

    sys_log(log, "CPARACFG_CHFS_MEMC_SWITCH                  = %s\n" ,  CPARACFG_CHFS_MEMC_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_CHFS_MEMC_NP_MODEL                = %s\n" ,  crfsnp_model_str(CPARACFG_CHFS_MEMC_NP_MODEL(cparacfg)));
    sys_log(log, "CPARACFG_CHFS_MEMC_BUCKET_NUM              = %u\n" ,  CPARACFG_CHFS_MEMC_BUCKET_NUM(cparacfg));
    sys_log(log, "CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM          = %s\n" ,  cpgd_model_str(CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM(cparacfg)));
    sys_log(log, "CPARACFG_CHFSMON_CONHASH_SWITCH            = %s\n" ,  CPARACFG_CHFSMON_CONHASH_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_CHFSMON_CONHASH_REPLICAS          = %u\n" ,  CPARACFG_CHFSMON_CONHASH_REPLICAS(cparacfg));

    sys_log(log, "CPARACFG_CSFS_MEMC_SWITCH                  = %s\n" ,  CPARACFG_CSFS_MEMC_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_CSFS_MEMC_NP_MODEL                = %s\n" ,  crfsnp_model_str(CPARACFG_CSFS_MEMC_NP_MODEL(cparacfg)));
    sys_log(log, "CPARACFG_CSFS_MEMC_BUCKET_NUM              = %u\n" ,  CPARACFG_CSFS_MEMC_BUCKET_NUM(cparacfg));
    sys_log(log, "CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM         = %s\n" ,  cpgd_model_str(CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM(cparacfg)));
    sys_log(log, "CPARACFG_CSFSMON_CONHASH_SWITCH            = %s\n" ,  CPARACFG_CSFSMON_CONHASH_SWITCH_STR(cparacfg));
    sys_log(log, "CPARACFG_CSFSMON_CONHASH_REPLICAS          = %u\n" ,  CPARACFG_CSFSMON_CONHASH_REPLICAS(cparacfg));

    sys_log(log, "CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT     = %u\n" ,  CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg));
    sys_log(log, "CPARACFG_NGX_EPOLL_TIMEOUT_MSEC            = %u\n" ,  CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg));

    sys_log(log, "CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP         = %u\n" ,  CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    sys_log(log, "CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP         = %u\n" ,  CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    sys_log(log, "CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP         = %u\n" ,  CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    sys_log(log, "CPARACFG_SFS_HTTP_REQ_NUM_PER_LOOP         = %u\n" ,  CPARACFG_SFS_HTTP_REQ_NUM_PER_LOOP(cparacfg));
    return;
}



#ifdef __cplusplus
}
#endif/*__cplusplus*/
