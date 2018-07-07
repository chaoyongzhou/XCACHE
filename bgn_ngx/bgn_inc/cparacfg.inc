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

#ifndef _CPARACFG_INC
#define _CPARACFG_INC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "type.h"

typedef struct
{
    UINT32    tcid; /*this cparacfg for which tcid*/
    UINT32    rank; /*this cparacfg for which rank*/

    UINT32    task_req_thread_max_num       ;
    UINT32    task_rsp_thread_max_num       ;
    UINT32    cthread_stack_max_size        ;
    UINT32    cthread_stack_guard_size      ;
    UINT32    task_req_handle_thread_switch ;
    UINT32    task_req_decode_thread_switch ;
    UINT32    task_rsp_decode_thread_switch ;
    UINT32    task_fwd_decode_thread_switch ;
    UINT32    cbase64_encode_switch         ;
    UINT32    task_encoding_rule            ;
    UINT32    task_slow_down_msec           ;
    UINT32    task_not_slow_down_max_times  ;
       int    csocket_so_sndbuff_size       ;/*for fwd rank only*/
       int    csocket_so_rcvbuff_size       ;/*for fwd rank only*/
       int    csocket_so_sndlowat_size      ;
       int    csocket_so_rcvlowat_size      ;
       int    csocket_so_sndtimeo_nsec      ;
       int    csocket_so_rcvtimeo_nsec      ;

    UINT32    csocket_so_keepalive_switch   ;
       int    csocket_tcp_keepidle_nsec     ;
       int    csocket_tcp_keepintvl_nsec    ;
       int    csocket_tcp_keepcnt_times     ;
       int    rsvd01;

    UINT32    csocket_unix_domain_switch    ;

    UINT32    csocket_send_once_max_size    ;/*for fwd rank only*/
    UINT32    csocket_recv_once_max_size    ;/*for fwd rank only*/
    UINT32    csocket_cnode_num             ;/*for fwd rank only*/
    UINT32    csocket_heartbeat_intvl_nsec  ;/*for fwd rank only*/

    UINT32    file_log_max_records          ;
    UINT32    file_log_name_with_date_switch;

    //UINT32    conn_keepalive_switch         ;/*internal communication keepalive by hearbeat, http connection by checking data transfering*/
    UINT32    conn_timeout_nsec             ;/*if no data tranfer in n seconds, shutdown the connection*/
    UINT32    timeout_max_num_per_loop      ;/*once cepoll loop shutdown the timeout connections to the max num*/

    UINT32    high_precision_time_switch    ;/*ONLY FOR DEBUG! give high precision in micro-second, reduce the affect of on-wall clock*/

    UINT32    ngx_bgn_over_http_switch      ;/*only for NGX_BGN_SWITCH == SWITCH_ON*/

    UINT32    crfsnp_try_retire_max_num     ; /* CRFSNP_TRY_RETIRE_MAX_NUM */
    UINT32    crfsnp_try_recycle_max_num    ; /* CRFSNP_TRY_RECYCLE_MAX_NUM */
    UINT32    crfs_memc_switch              ; /* CRFS_MEMC_SWITCH */
    uint8_t   rsvd02;
    uint8_t   crfs_memc_np_model;           ;
    uint16_t  crfs_memc_cpgd_block_num      ;

    uint16_t  rsvd03;
    uint16_t  crfsmon_conhash_replicas      ; /* CRFSMON_CONHASH_REPLICAS */
    UINT32    crfsmon_conhash_switch        ; /* CRFSMON_CONHASH_SWITCH */
    UINT32    crfsmon_hot_path_switch       ; /* CRFSMON_HOT_PATH_SWITCH */

    UINT32    chfs_memc_switch              ; /* CHFS_MEMC_SWITCH */
    uint8_t   rsvd04;
    uint8_t   chfs_memc_np_model;           ;
    uint16_t  chfs_memc_cpgd_block_num      ;
    uint32_t  chfs_memc_bucket_num          ;
    uint32_t  rsvd05;

    uint16_t  rsvd06;
    uint16_t  chfsmon_conhash_replicas      ; /* CHFSMON_CONHASH_REPLICAS */
    UINT32    chfsmon_conhash_switch        ; /* CHFSMON_CONHASH_SWITCH */

    UINT32    csfs_memc_switch              ; /* CSFS_MEMC_SWITCH */
    uint8_t   rsvd07;
    uint8_t   csfs_memc_np_model;           ;
    uint16_t  csfs_memc_csfsd_block_num     ;
    uint32_t  csfs_memc_bucket_num          ;
    uint32_t  rsvd08;
    uint16_t  rsvd09;
    uint16_t  csfsmon_conhash_replicas      ; /* CSFSMON_CONHASH_REPLICAS */
    UINT32    csfsmon_conhash_switch        ; /* CSFSMON_CONHASH_SWITCH */

    uint32_t  ngx_lua_output_blocking_lowat ; /* if buff to send is more than that, block for next sending;otherwise, return and prepare data for next sending*/
    uint32_t  ngx_epoll_timeout_msec        ;

    uint32_t  ngx_http_req_num_per_loop     ; /*0 means handle all http requests per loop*/
    uint32_t  rfs_http_req_num_per_loop     ; /*0 means handle all http requests per loop*/
    uint32_t  hfs_http_req_num_per_loop     ; /*0 means handle all http requests per loop*/
    uint32_t  sfs_http_req_num_per_loop     ; /*0 means handle all http requests per loop*/
    CSTRING   ssl_certificate_file_name_cstr;
    CSTRING   ssl_private_key_file_name_cstr;

    UINT32    tdns_resolve_switch           ; /*TDNS_RESOLVE_SWITCH*/
    UINT32    tdns_resolve_timeout_nsec     ; /*TDNS resolve domain timeout in seconds*/

    UINT32    log_level_tab[ SEC_NONE_END ] ;
}CPARACFG;

#define CPARACFG_TCID(cparacfg)                                     ((cparacfg)->tcid)
#define CPARACFG_TCID_STR(cparacfg)                                 (c_word_to_ipv4(CPARACFG_TCID(cparacfg)))
#define CPARACFG_RANK(cparacfg)                                     ((cparacfg)->rank)

#define CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg)                  ((cparacfg)->task_req_thread_max_num       )
#define CPARACFG_TASK_RSP_THREAD_MAX_NUM(cparacfg)                  ((cparacfg)->task_rsp_thread_max_num       )
#define CPARACFG_CTHREAD_STACK_MAX_SIZE(cparacfg)                   ((cparacfg)->cthread_stack_max_size        )
#define CPARACFG_CTHREAD_STACK_GUARD_SIZE(cparacfg)                 ((cparacfg)->cthread_stack_guard_size      )
#define CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH(cparacfg)            ((cparacfg)->task_req_handle_thread_switch )
#define CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH(cparacfg)            ((cparacfg)->task_req_decode_thread_switch )
#define CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH(cparacfg)            ((cparacfg)->task_rsp_decode_thread_switch )
#define CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH(cparacfg)            ((cparacfg)->task_fwd_decode_thread_switch )
#define CPARACFG_CBASE64_ENCODE_SWITCH(cparacfg)                    ((cparacfg)->cbase64_encode_switch         )
#define CPARACFG_TASK_ENCODING_RULE(cparacfg)                       ((cparacfg)->task_encoding_rule            )

#define CPARACFG_TASK_SLOW_DOWN_MSEC(cparacfg)                      ((cparacfg)->task_slow_down_msec           )
#define CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES(cparacfg)             ((cparacfg)->task_not_slow_down_max_times  )

#define CPARACFG_CSOCKET_SO_SNDBUFF_SIZE(cparacfg)                  ((cparacfg)->csocket_so_sndbuff_size       )
#define CPARACFG_CSOCKET_SO_RCVBUFF_SIZE(cparacfg)                  ((cparacfg)->csocket_so_rcvbuff_size       )

#define CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE(cparacfg)                 ((cparacfg)->csocket_so_sndlowat_size      )
#define CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE(cparacfg)                 ((cparacfg)->csocket_so_rcvlowat_size      )

#define CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC(cparacfg)                 ((cparacfg)->csocket_so_sndtimeo_nsec      )
#define CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC(cparacfg)                 ((cparacfg)->csocket_so_rcvtimeo_nsec      )

#define CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(cparacfg)              ((cparacfg)->csocket_so_keepalive_switch   )
#define CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC(cparacfg)                ((cparacfg)->csocket_tcp_keepidle_nsec     )
#define CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC(cparacfg)               ((cparacfg)->csocket_tcp_keepintvl_nsec    )
#define CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES(cparacfg)                ((cparacfg)->csocket_tcp_keepcnt_times     )

#define CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(cparacfg)               ((cparacfg)->csocket_unix_domain_switch    )

#define CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE(cparacfg)               ((cparacfg)->csocket_send_once_max_size    )
#define CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE(cparacfg)               ((cparacfg)->csocket_recv_once_max_size    )
#define CPARACFG_CSOCKET_CNODE_NUM(cparacfg)                        ((cparacfg)->csocket_cnode_num             )

#define CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC(cparacfg)             ((cparacfg)->csocket_heartbeat_intvl_nsec  )
#define CPARACFG_FILE_LOG_MAX_RECORDS(cparacfg)                     ((cparacfg)->file_log_max_records          )
#define CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH(cparacfg)           ((cparacfg)->file_log_name_with_date_switch)
//#define CPARACFG_CONN_KEEPALIVE_SWITCH(cparacfg)                    ((cparacfg)->conn_keepalive_switch)
#define CPARACFG_CONN_TIMEOUT_NSEC(cparacfg)                        ((cparacfg)->conn_timeout_nsec)
#define CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg)                 ((cparacfg)->timeout_max_num_per_loop)
#define CPARACFG_LOG_LEVEL_TAB(cparacfg)                            ((cparacfg)->log_level_tab)

#define CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)               ((cparacfg)->high_precision_time_switch)
#define CPARACFG_NGX_BGN_OVER_HTTP_SWITCH(cparacfg)                 ((cparacfg)->ngx_bgn_over_http_switch)

#define CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM(cparacfg)                ((cparacfg)->crfsnp_try_retire_max_num)
#define CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM(cparacfg)               ((cparacfg)->crfsnp_try_recycle_max_num)
#define CPARACFG_CRFS_MEMC_SWITCH(cparacfg)                         ((cparacfg)->crfs_memc_switch)
#define CPARACFG_CRFS_MEMC_NP_MODEL(cparacfg)                       ((cparacfg)->crfs_memc_np_model)
#define CPARACFG_CRFS_MEMC_CPGD_BLOCK_NUM(cparacfg)                 ((cparacfg)->crfs_memc_cpgd_block_num)
#define CPARACFG_CRFSMON_CONHASH_SWITCH(cparacfg)                   ((cparacfg)->crfsmon_conhash_switch)
#define CPARACFG_CRFSMON_CONHASH_REPLICAS(cparacfg)                 ((cparacfg)->crfsmon_conhash_replicas)
#define CPARACFG_CRFSMON_HOT_PATH_SWITCH(cparacfg)                  ((cparacfg)->crfsmon_hot_path_switch)

#define CPARACFG_CHFS_MEMC_SWITCH(cparacfg)                         ((cparacfg)->chfs_memc_switch)
#define CPARACFG_CHFS_MEMC_NP_MODEL(cparacfg)                       ((cparacfg)->chfs_memc_np_model)
#define CPARACFG_CHFS_MEMC_BUCKET_NUM(cparacfg)                     ((cparacfg)->chfs_memc_bucket_num)
#define CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM(cparacfg)                 ((cparacfg)->chfs_memc_cpgd_block_num)
#define CPARACFG_CHFSMON_CONHASH_SWITCH(cparacfg)                   ((cparacfg)->chfsmon_conhash_switch)
#define CPARACFG_CHFSMON_CONHASH_REPLICAS(cparacfg)                 ((cparacfg)->chfsmon_conhash_replicas)

#define CPARACFG_CSFS_MEMC_SWITCH(cparacfg)                         ((cparacfg)->csfs_memc_switch)
#define CPARACFG_CSFS_MEMC_NP_MODEL(cparacfg)                       ((cparacfg)->csfs_memc_np_model)
#define CPARACFG_CSFS_MEMC_BUCKET_NUM(cparacfg)                     ((cparacfg)->csfs_memc_bucket_num)
#define CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM(cparacfg)                ((cparacfg)->csfs_memc_csfsd_block_num)
#define CPARACFG_CSFSMON_CONHASH_SWITCH(cparacfg)                   ((cparacfg)->csfsmon_conhash_switch)
#define CPARACFG_CSFSMON_CONHASH_REPLICAS(cparacfg)                 ((cparacfg)->csfsmon_conhash_replicas)

#define CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg)            ((cparacfg)->ngx_lua_output_blocking_lowat)
#define CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg)                   ((cparacfg)->ngx_epoll_timeout_msec)

#define CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg)                ((cparacfg)->ngx_http_req_num_per_loop)
#define CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)                ((cparacfg)->rfs_http_req_num_per_loop)
#define CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)                ((cparacfg)->hfs_http_req_num_per_loop)
#define CPARACFG_SFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)                ((cparacfg)->sfs_http_req_num_per_loop)

#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg)           (&((cparacfg)->ssl_certificate_file_name_cstr))
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg)           (&((cparacfg)->ssl_private_key_file_name_cstr))

#define CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)                      ((cparacfg)->tdns_resolve_switch)
#define CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC(cparacfg)                ((cparacfg)->tdns_resolve_timeout_nsec)

#define CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH_STR(cparacfg)        (c_switch_to_str(CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH(cparacfg)))
#define CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH_STR(cparacfg)        (c_switch_to_str(CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH(cparacfg)))
#define CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH_STR(cparacfg)        (c_switch_to_str(CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH(cparacfg)))
#define CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH_STR(cparacfg)        (c_switch_to_str(CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH(cparacfg)))
#define CPARACFG_CBASE64_ENCODE_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CBASE64_ENCODE_SWITCH(cparacfg)))
#define CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH_STR(cparacfg)       (c_switch_to_str(CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH(cparacfg)))
//#define CPARACFG_CONN_KEEPALIVE_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CONN_KEEPALIVE_SWITCH(cparacfg)))
#define CPARACFG_HIGH_PRECISION_TIME_SWITCH_STR(cparacfg)           (c_switch_to_str(CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)))
#define CPARACFG_NGX_BGN_OVER_HTTP_SWITCH_STR(cparacfg)             (c_switch_to_str(CPARACFG_NGX_BGN_OVER_HTTP_SWITCH(cparacfg)))
#define CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH_STR(cparacfg)          (c_switch_to_str(CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(cparacfg)))

#define CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH_STR(cparacfg)           (c_switch_to_str(CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(cparacfg)))

#define CPARACFG_CRFS_MEMC_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CRFS_MEMC_SWITCH(cparacfg)))
#define CPARACFG_CRFSMON_CONHASH_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CRFSMON_CONHASH_SWITCH(cparacfg)))
#define CPARACFG_CRFSMON_HOT_PATH_SWITCH_STR(cparacfg)              (c_switch_to_str(CPARACFG_CRFSMON_HOT_PATH_SWITCH(cparacfg)))

#define CPARACFG_CHFS_MEMC_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CHFS_MEMC_SWITCH(cparacfg)))
#define CPARACFG_CHFSMON_CONHASH_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CHFSMON_CONHASH_SWITCH(cparacfg)))

#define CPARACFG_CSFS_MEMC_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CSFS_MEMC_SWITCH(cparacfg)))
#define CPARACFG_CSFSMON_CONHASH_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CSFSMON_CONHASH_SWITCH(cparacfg)))

#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_STR(cparacfg)            ((char *)cstring_get_str(CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg)))
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_STR(cparacfg)            ((char *)cstring_get_str(CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg)))

#define CPARACFG_TDNS_RESOLVE_SWITCH_STR(cparacfg)                  (c_switch_to_str(CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)))


#define MEM_BUFF_128B ( 128      )
#define MEM_BUFF_512B ( 512      )
#define MEM_BUFF_1K   ( 1024     )
#define MEM_BUFF_8K   ( 8192     )
#define MEM_BUFF_16K  ( 16384    )
#define MEM_BUFF_32K  ( 32768    )
#define MEM_BUFF_64K  ( 65536    )
#define MEM_BUFF_128K ( 131072   )
#define MEM_BUFF_1M   ( 1048576  )
#define MEM_BUFF_8M   ( 8388608  )
#define MEM_BUFF_16M  ( 16777216 )
#define MEM_BUFF_32M  ( 33554432 )
#define MEM_BUFF_64M  ( 67108864 )

#define FILE_LOG_RECORDS_400   ( 400      )
#define FILE_LOG_RECORDS_001K  ( 1000     )
#define FILE_LOG_RECORDS_002K  ( 2000     )
#define FILE_LOG_RECORDS_004K  ( 4000     )
#define FILE_LOG_RECORDS_008K  ( 8000     )
#define FILE_LOG_RECORDS_010K  ( 10000    )
#define FILE_LOG_RECORDS_020K  ( 20000    )
#define FILE_LOG_RECORDS_040K  ( 40000    )
#define FILE_LOG_RECORDS_080K  ( 80000    )
#define FILE_LOG_RECORDS_100K  ( 100000   )
#define FILE_LOG_RECORDS_001M  ( 1000000  )
#define FILE_LOG_RECORDS_002M  ( 2000000  )
#define FILE_LOG_RECORDS_004M  ( 4000000  )
#define FILE_LOG_RECORDS_010M  ( 10000000 )
#define FILE_LOG_RECORDS_020M  ( 20000000 )

#define CTHREAD_STACK_MAX_SIZE_008K ( 8192    )
#define CTHREAD_STACK_MAX_SIZE_016K ( 16384   )
#define CTHREAD_STACK_MAX_SIZE_032K ( 32768   )
#define CTHREAD_STACK_MAX_SIZE_064K ( 65536   )
#define CTHREAD_STACK_MAX_SIZE_128K ( 131072  )
#define CTHREAD_STACK_MAX_SIZE_256K ( 262144  )
#define CTHREAD_STACK_MAX_SIZE_512K ( 524288  )
#define CTHREAD_STACK_MAX_SIZE_001M ( 1048576 )
#define CTHREAD_STACK_MAX_SIZE_002M ( 2097152 )
#define CTHREAD_STACK_MAX_SIZE_004M ( 4194304 )
#define CTHREAD_STACK_MAX_SIZE_008M ( 8388608 )

#define CTHREAD_STACK_GUARD_SIZE_001K ( 1024    )
#define CTHREAD_STACK_GUARD_SIZE_002K ( 2048    )
#define CTHREAD_STACK_GUARD_SIZE_004K ( 4096    )
#define CTHREAD_STACK_GUARD_SIZE_008K ( 8192    )
#define CTHREAD_STACK_GUARD_SIZE_016K ( 16384   )
#define CTHREAD_STACK_GUARD_SIZE_032K ( 32768   )
#define CTHREAD_STACK_GUARD_SIZE_064K ( 65536   )
#define CTHREAD_STACK_GUARD_SIZE_128K ( 131072  )
#define CTHREAD_STACK_GUARD_SIZE_256K ( 262144  )
#define CTHREAD_STACK_GUARD_SIZE_512K ( 524288  )
#define CTHREAD_STACK_GUARD_SIZE_001M ( 1048576 )
#define CTHREAD_STACK_GUARD_SIZE_002M ( 2097152 )
#define CTHREAD_STACK_GUARD_SIZE_004M ( 4194304 )
#define CTHREAD_STACK_GUARD_SIZE_008M ( 8388608 )

/*------------------------------------------------- default value definition BEG -------------------------------------------------*/
#define CPARACFG_TASK_REQ_THREAD_MAX_NUM_DEF                     512
#define CPARACFG_TASK_RSP_THREAD_MAX_NUM_DEF                     32
#define CPARACFG_CTHREAD_STACK_MAX_SIZE_DEF                      CTHREAD_STACK_MAX_SIZE_064K
#define CPARACFG_CTHREAD_STACK_GUARD_SIZE_DEF                    CTHREAD_STACK_GUARD_SIZE_004K

#define CPARACFG_TASK_SLOW_DOWN_MSEC_DEF                         3
#define CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES_DEF                512

#define CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH_DEF               SWITCH_ON
#define CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH_DEF               SWITCH_OFF
#define CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH_DEF               SWITCH_ON
#define CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH_DEF               SWITCH_ON
#define CPARACFG_CBASE64_ENCODE_SWITCH_DEF                       SWITCH_OFF
#define CPARACFG_TASK_ENCODING_RULE_DEF                          BYTE_ENCODING_RULE

#define CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC_DEF                10
#define CPARACFG_CSOCKET_SO_SNDBUFF_SIZE_DEF                     MEM_BUFF_64K
#define CPARACFG_CSOCKET_SO_RCVBUFF_SIZE_DEF                     MEM_BUFF_64K
#define CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC_DEF                    15
#define CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC_DEF                    15
#define CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE_DEF                    0
#define CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE_DEF                    0
#define CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH_DEF                 SWITCH_OFF
#define CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC_DEF                   10
#define CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC_DEF                  5
#define CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES_DEF                   3
#define CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH_DEF                  SWITCH_OFF
#define CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE_DEF                  MEM_BUFF_64K
#define CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE_DEF                  MEM_BUFF_64K
#define CPARACFG_CSOCKET_CNODE_NUM_DEF                           4

#define CPARACFG_FILE_LOG_MAX_RECORDS_DEF                        FILE_LOG_RECORDS_001M
#define CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH_DEF              SWITCH_OFF

#define CPARACFG_CONSOLE_TERM_SWITCH_DEF                         SWITCH_OFF

#define CPARACFG_CONN_TIMEOUT_NSEC_DEF                           20
#define CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP_DEF                    1024
#define CPARACFG_HIGH_PRECISION_TIME_SWITCH_DEF                  SWITCH_OFF
#define CPARACFG_NGX_BGN_OVER_HTTP_SWITCH_DEF                    SWITCH_OFF

#define CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM_DEF                   128
#define CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM_DEF                  512
#define CPARACFG_CRFS_MEMC_SWITCH_DEF                            SWITCH_OFF
#define CPARACFG_CRFS_MEMC_NP_MODEL_DEF                          CRFSNP_512M_MODEL
#define CPARACFG_CRFS_MEMC_CPGD_BLOCK_NUM_DEF                    CPGD_001GB_BLOCK_NUM

#define CPARACFG_CRFSMON_CONHASH_SWITCH_DEF                      SWITCH_ON
#define CPARACFG_CRFSMON_CONHASH_REPLICAS_DEF                    4096
#define CPARACFG_CRFSMON_HOT_PATH_SWITCH_DEF                     SWITCH_ON

#define CPARACFG_CHFS_MEMC_SWITCH_DEF                            SWITCH_OFF
#define CPARACFG_CHFS_MEMC_NP_MODEL_DEF                          CHFSNP_128M_MODEL
#define CPARACFG_CHFS_MEMC_BUCKET_NUM_DEF                        CHFSNP_BUCKET_NUM
#define CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM_DEF                    CPGD_001GB_BLOCK_NUM

#define CPARACFG_CHFSMON_CONHASH_SWITCH_DEF                      SWITCH_ON
#define CPARACFG_CHFSMON_CONHASH_REPLICAS_DEF                    4096

#define CPARACFG_CSFS_MEMC_SWITCH_DEF                            SWITCH_OFF
#define CPARACFG_CSFS_MEMC_NP_MODEL_DEF                          CSFSNP_128M_MODEL
#define CPARACFG_CSFS_MEMC_BUCKET_NUM_DEF                        CSFSNP_BUCKET_NUM
#define CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM_DEF                   CSFSD_001GB_BLOCK_NUM
#define CPARACFG_CSFSMON_CONHASH_SWITCH_DEF                      SWITCH_ON
#define CPARACFG_CSFSMON_CONHASH_REPLICAS_DEF                    4096

#define CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT_DEF               MEM_BUFF_32K
#define CPARACFG_NGX_EPOLL_TIMEOUT_MSEC_DEF                      1

#define CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP_DEF                   0 /*0 means handle all*/
#define CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP_DEF                   0 /*0 means handle all*/
#define CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP_DEF                   0 /*0 means handle all*/
#define CPARACFG_SFS_HTTP_REQ_NUM_PER_LOOP_DEF                   0 /*0 means handle all*/
#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR_DEF              ((uint8_t *)"certificate.pem")
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR_DEF              ((uint8_t *)"private_key.pem")

#define CPARACFG_TDNS_RESOLVE_SWITCH_DEF                         SWITCH_ON
#define CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC_DEF                   30 /*30 seconds*/

#define CPARACFG_SET_DEFAULT(cparacfg, macro_name)  \
            macro_name(cparacfg)  = macro_name##_DEF

#define CPARACFG_SET_STR_DEFAULT(cparacfg, macro_name)  \
            cstring_init(macro_name(cparacfg), macro_name##_DEF)

/*------------------------------------------------- default value definition END -------------------------------------------------*/

#define    CPARACFG_DEFAULT_GET()                        (TASK_BRD_CPARACFG(task_brd_default_get()))

#define    CPARACFG_DEFAULT_MAP(macro_name) \
                (NULL_PTR == CPARACFG_DEFAULT_GET() ? (macro_name##_DEF): macro_name(CPARACFG_DEFAULT_GET()))

#define    CPARACFG_DEFAULT_STR_MAP(macro_name) \
                (NULL_PTR == CPARACFG_DEFAULT_GET() ? (char *)(macro_name##_DEF): (char *)cstring_get_str(macro_name(CPARACFG_DEFAULT_GET())))

#define    TASK_REQ_THREAD_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_TASK_REQ_THREAD_MAX_NUM)
#define    TASK_RSP_THREAD_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_TASK_RSP_THREAD_MAX_NUM)

#define    TASK_SLOW_DOWN_MSEC                           CPARACFG_DEFAULT_MAP(CPARACFG_TASK_SLOW_DOWN_MSEC)
#define    TASK_NOT_SLOW_DOWN_MAX_TIMES                  CPARACFG_DEFAULT_MAP(CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES)

#define    CSOCKET_HEARTBEAT_INTVL_NSEC                  CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC)

#define    CSOCKET_SO_SNDBUFF_SIZE                       CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_SNDBUFF_SIZE)
#define    CSOCKET_SO_RCVBUFF_SIZE                       CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_RCVBUFF_SIZE)

#define    CSOCKET_SO_SNDTIMEO_NSEC                      CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC)
#define    CSOCKET_SO_RCVTIMEO_NSEC                      CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC)

#define    CSOCKET_SO_RCVLOWAT_SIZE                      CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE)
#define    CSOCKET_SO_SNDLOWAT_SIZE                      CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE)

#define    CSOCKET_SO_KEEPALIVE_SWITCH                   CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH)
#define    CSOCKET_TCP_KEEPIDLE_NSEC                     CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC)
#define    CSOCKET_TCP_KEEPINTVL_NSEC                    CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC)
#define    CSOCKET_TCP_KEEPCNT_TIMES                     CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES)

#define    CSOCKET_UNIX_DOMAIN_SWITCH                    CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH)

#define    CSOCKET_SEND_ONCE_MAX_SIZE                    CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE)
#define    CSOCKET_RECV_ONCE_MAX_SIZE                    CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE)
#define    CSOCKET_CNODE_NUM                             CPARACFG_DEFAULT_MAP(CPARACFG_CSOCKET_CNODE_NUM)

#define    CONN_TIMEOUT_NSEC                             CPARACFG_DEFAULT_MAP(CPARACFG_CONN_TIMEOUT_NSEC)
#define    CONN_TIMEOUT_MAX_NUM_PER_LOOP                 CPARACFG_DEFAULT_MAP(CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP)
#define    HIGH_PRECISION_TIME_SWITCH                    CPARACFG_DEFAULT_MAP(CPARACFG_HIGH_PRECISION_TIME_SWITCH)

#define    NGX_BGN_OVER_HTTP_SWITCH                      CPARACFG_DEFAULT_MAP(CPARACFG_NGX_BGN_OVER_HTTP_SWITCH)

#define    CRFSNP_TRY_RETIRE_MAX_NUM                     CPARACFG_DEFAULT_MAP(CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM)
#define    CRFSNP_TRY_RECYCLE_MAX_NUM                    CPARACFG_DEFAULT_MAP(CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM)
#define    CRFS_MEMC_SWITCH                              CPARACFG_DEFAULT_MAP(CPARACFG_CRFS_MEMC_SWITCH)
#define    CRFS_MEMC_NP_MODEL                            CPARACFG_DEFAULT_MAP(CPARACFG_CRFS_MEMC_NP_MODEL)
#define    CRFS_MEMC_CPGD_BLOCK_NUM                      CPARACFG_DEFAULT_MAP(CPARACFG_CRFS_MEMC_CPGD_BLOCK_NUM)
#define    CRFSMON_CONHASH_SWITCH                        CPARACFG_DEFAULT_MAP(CPARACFG_CRFSMON_CONHASH_SWITCH)
#define    CRFSMON_CONHASH_REPLICAS                      CPARACFG_DEFAULT_MAP(CPARACFG_CRFSMON_CONHASH_REPLICAS)
#define    CRFSMON_HOT_PATH_SWITCH                       CPARACFG_DEFAULT_MAP(CPARACFG_CRFSMON_HOT_PATH_SWITCH)

#define    CHFS_MEMC_SWITCH                              CPARACFG_DEFAULT_MAP(CPARACFG_CHFS_MEMC_SWITCH)
#define    CHFS_MEMC_NP_MODEL                            CPARACFG_DEFAULT_MAP(CPARACFG_CHFS_MEMC_NP_MODEL)
#define    CHFS_MEMC_BUCKET_NUM                          CPARACFG_DEFAULT_MAP(CPARACFG_CHFS_MEMC_BUCKET_NUM)
#define    CHFS_MEMC_CPGD_BLOCK_NUM                      CPARACFG_DEFAULT_MAP(CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM)
#define    CHFSMON_CONHASH_SWITCH                        CPARACFG_DEFAULT_MAP(CPARACFG_CHFSMON_CONHASH_SWITCH)
#define    CHFSMON_CONHASH_REPLICAS                      CPARACFG_DEFAULT_MAP(CPARACFG_CHFSMON_CONHASH_REPLICAS)

#define    CSFS_MEMC_SWITCH                              CPARACFG_DEFAULT_MAP(CPARACFG_CSFS_MEMC_SWITCH)
#define    CSFS_MEMC_NP_MODEL                            CPARACFG_DEFAULT_MAP(CPARACFG_CSFS_MEMC_NP_MODEL)
#define    CSFS_MEMC_BUCKET_NUM                          CPARACFG_DEFAULT_MAP(CPARACFG_CSFS_MEMC_BUCKET_NUM)
#define    CSFS_MEMC_CSFSD_BLOCK_NUM                     CPARACFG_DEFAULT_MAP(CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM)
#define    CSFSMON_CONHASH_SWITCH                        CPARACFG_DEFAULT_MAP(CPARACFG_CSFSMON_CONHASH_SWITCH)
#define    CSFSMON_CONHASH_REPLICAS                      CPARACFG_DEFAULT_MAP(CPARACFG_CSFSMON_CONHASH_REPLICAS)

#define    NGX_LUA_OUTPUT_BLOCKING_LOWAT                 CPARACFG_DEFAULT_MAP(CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT)
#define    NGX_EPOLL_TIMEOUT_MSEC                        CPARACFG_DEFAULT_MAP(CPARACFG_NGX_EPOLL_TIMEOUT_MSEC)

#define    NGX_HTTP_REQ_NUM_PER_LOOP                     CPARACFG_DEFAULT_MAP(CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP)
#define    RFS_HTTP_REQ_NUM_PER_LOOP                     CPARACFG_DEFAULT_MAP(CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP)
#define    HFS_HTTP_REQ_NUM_PER_LOOP                     CPARACFG_DEFAULT_MAP(CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP)
#define    SFS_HTTP_REQ_NUM_PER_LOOP                     CPARACFG_DEFAULT_MAP(CPARACFG_SFS_HTTP_REQ_NUM_PER_LOOP)

#define    SSL_CERTIFICATE_FILE_NAME                     CPARACFG_DEFAULT_STR_MAP(CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR)
#define    SSL_PRIVATE_KEY_FILE_NAME                     CPARACFG_DEFAULT_STR_MAP(CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR)

#define    TDNS_RESOLVE_SWITCH                           CPARACFG_DEFAULT_MAP(CPARACFG_TDNS_RESOLVE_SWITCH)
#define    TDNS_RESOLVE_TIMEOUT_NSEC                     CPARACFG_DEFAULT_MAP(CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC)

#endif/*_CPARACFG_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
