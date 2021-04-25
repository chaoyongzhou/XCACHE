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

    UINT32    proc_core_id; /*bind cpu core id*/

    UINT32    task_req_thread_max_num       ;
    UINT32    task_rsp_thread_max_num       ;
    UINT32    cthread_stack_max_size        ;
    UINT32    cthread_stack_guard_size      ;

    UINT32    task_slow_down_msec           ;
    UINT32    task_live_nsec                ;
    UINT32    task_zombie_nsec              ;
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

    UINT32    cepoll_event_max_num          ;/* CEPOLL_EVENT_MAX_NUM */
    UINT32    srv_accept_max_num            ;/* SRV_ACCEPT_MAX_NUM */

    //UINT32    conn_keepalive_switch         ;/*internal communication keepalive by hearbeat, http connection by checking data transfering*/
    UINT32    conn_timeout_nsec             ;/*if no data tranfer in n seconds, shutdown the connection*/
    UINT32    timeout_max_num_per_loop      ;/*once cepoll loop shutdown the timeout connections to the max num*/
    UINT32    cdns_timeout_nsec             ;/*if no data tranfer in n seconds, shutdown the connection*/

    UINT32    dns_cache_switch              ;/*dns resolver query dns cache if switch on*/
    UINT32    dns_cache_expired_nsec        ;/*dns resolved result would be expired in nsec*/

    UINT32    high_precision_time_switch    ;/*ONLY FOR DEBUG! give high precision in micro-second, reduce the affect of on-wall clock*/

    REAL      cxfsnp_max_used_ratio         ; /* CXFSNP_MAX_USED_RATIO    */
    REAL      cxfsdn_max_used_ratio         ; /* CXFSDN_MAX_USED_RATIO    */

    UINT32    cxfsnp_try_retire_max_num     ; /* CXFSNP_TRY_RETIRE_MAX_NUM  */
    UINT32    cxfsnp_try_recycle_max_num    ; /* CXFSNP_TRY_RECYCLE_MAX_NUM */
    UINT32    cxfsnp_cache_in_mem_switch    ; /* CXFSNP_CACHE_IN_MEM_SWITCH */
    UINT32    cxfsdn_cache_in_mem_switch    ; /* CXFSDN_CACHE_IN_MEM_SWITCH */

    UINT32    cxfsdn_camd_switch            ; /* CXFSDN_CAMD_SWITCH*/
    UINT32    cxfsdn_camd_mem_disk_size     ; /* CXFSDN_CAMD_MEM_DISK_SIZE   */

    UINT32    cxfs_lru_model_switch         ; /* CXFS_LRU_MODEL_SWITCH */
    UINT32    cxfs_fifo_model_switch        ; /* CXFS_FIFO_MODEL_SWITCH */

    UINT32    cxfs_camd_overhead_switch     ; /* CXFS_CAMD_OVERHEAD_SWITCH */
    UINT32    cxfs_camd_discard_ratio       ; /* CXFS_CAMD_DISCARD_RATIO */

    CSTRING   cxfsnbd_device_name_cstr      ;
    UINT32    cxfsnbd_device_size           ; /*CXFSNBD_DEV_SIZE*/
    UINT32    cxfsnbd_block_size            ; /*CXFSNBD_BLK_SIZE*/
    UINT32    cxfsnbd_timeout_nsec          ; /*CXFSNBD_TIMEOUT_NSEC*/

    uint16_t  rsvd03;
    uint16_t  cmon_conhash_replicas         ; /* CMON_CONHASH_REPLICAS */
    uint32_t  rsvd04;
    UINT32    cmon_conhash_switch           ; /* CMON_CONHASH_SWITCH */
    UINT32    cmon_maglev_switch            ; /* CMON_MAGLEV_SWITCH */

    UINT32    cmon_hot_path_switch          ; /* CMON_HOT_PATH_SWITCH */

    uint32_t  ngx_lua_output_blocking_lowat ; /* if buff to send is more than that, block for next sending;otherwise, return and prepare data for next sending*/
    uint32_t  ngx_epoll_timeout_msec        ;

    uint32_t  ngx_http_req_num_per_loop     ; /*0 means handle all http requests per loop*/
    uint32_t  xfs_http_req_num_per_loop     ; /*0 means handle all http requests per loop*/
    CSTRING   ssl_certificate_file_name_cstr;
    CSTRING   ssl_private_key_file_name_cstr;

    UINT32    tdns_resolve_switch           ; /*TDNS_RESOLVE_SWITCH*/
    UINT32    tdns_resolve_timeout_nsec     ; /*TDNS resolve domain timeout in seconds*/

    UINT32    camd_ssd_aio_req_max_num;    /*default: 8*/
    UINT32    camd_sata_aio_req_max_num;   /*default: 8*/

    UINT32    camd_sata_degrade_ssd_switch;/*default: on*/

    UINT32    camd_ssd_upgrade_mem_switch; /*default: on*/
    UINT32    camd_sata_upgrade_mem_switch;/*default: on*/

    UINT32    camd_check_page_used_switch; /*default: off*/

    UINT32    cmc_try_retire_max_num;      /*default: 8*/
    UINT32    cmc_try_recycle_max_num;     /*default: 128*/
    UINT32    cmc_scan_retire_max_num;     /*default: 256*/

    UINT32    cmc_flow_control_switch;     /*default: on*/
    UINT32    cmc_process_degrade_max_num; /*default: 8*/
    UINT32    cmc_scan_degrade_max_num;    /*default: 256*/

    REAL      cmc_degrade_hi_ratio;        /*default: 0.90*/
    REAL      cmc_degrade_md_ratio;        /*default: 0.85*/
    REAL      cmc_degrade_lo_ratio;        /*default: 0.80*/

    UINT32    cmc_lru_model_switch;        /* CMC_LRU_MODEL_SWITCH */
    UINT32    cmc_fifo_model_switch;       /* CMC_FIFO_MODEL_SWITCH */

    UINT32    cdc_try_retire_max_num;      /*default: 8*/
    UINT32    cdc_try_recycle_max_num;     /*default: 128*/
    UINT32    cdc_scan_retire_max_num;     /*default: 128*/

    UINT32    cdc_read_cache_switch;       /*default: off*/
    UINT32    cdc_flow_control_switch;     /*default: on*/
    UINT32    cdc_process_degrade_max_num; /*default: 8*/
    UINT32    cdc_scan_degrade_max_num;    /*default: 256*/

    REAL      cdc_degrade_hi_ratio;        /*default: 0.90*/
    REAL      cdc_degrade_md_ratio;        /*default: 0.85*/
    REAL      cdc_degrade_lo_ratio;        /*default: 0.80*/

    UINT32    cdc_lru_model_switch;        /* CDC_LRU_MODEL_SWITCH */
    UINT32    cdc_fifo_model_switch;       /* CDC_FIFO_MODEL_SWITCH */

    UINT32    log_level_tab[ SEC_NONE_END ] ;
}CPARACFG;

#define CPARACFG_TCID(cparacfg)                                     ((cparacfg)->tcid)
#define CPARACFG_TCID_STR(cparacfg)                                 (c_word_to_ipv4(CPARACFG_TCID(cparacfg)))
#define CPARACFG_RANK(cparacfg)                                     ((cparacfg)->rank)

#define CPARACFG_PROC_CORE_ID(cparacfg)                             ((cparacfg)->proc_core_id)

#define CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg)                  ((cparacfg)->task_req_thread_max_num       )
#define CPARACFG_TASK_RSP_THREAD_MAX_NUM(cparacfg)                  ((cparacfg)->task_rsp_thread_max_num       )
#define CPARACFG_CTHREAD_STACK_MAX_SIZE(cparacfg)                   ((cparacfg)->cthread_stack_max_size        )
#define CPARACFG_CTHREAD_STACK_GUARD_SIZE(cparacfg)                 ((cparacfg)->cthread_stack_guard_size      )

#define CPARACFG_TASK_SLOW_DOWN_MSEC(cparacfg)                      ((cparacfg)->task_slow_down_msec           )
#define CPARACFG_TASK_LIVE_NSEC(cparacfg)                           ((cparacfg)->task_live_nsec                )
#define CPARACFG_TASK_ZOMBIE_NSEC(cparacfg)                         ((cparacfg)->task_zombie_nsec              )

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
//#define CPARACFG_CONN_KEEPALIVE_SWITCH(cparacfg)                    ((cparacfg)->conn_keepalive_switch)

#define CPARACFG_CEPOLL_EVENT_MAX_NUM(cparacfg)                     ((cparacfg)->cepoll_event_max_num)

#define CPARACFG_SRV_ACCEPT_MAX_NUM(cparacfg)                       ((cparacfg)->srv_accept_max_num)

#define CPARACFG_CONN_TIMEOUT_NSEC(cparacfg)                        ((cparacfg)->conn_timeout_nsec)
#define CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg)                 ((cparacfg)->timeout_max_num_per_loop)
#define CPARACFG_CDNS_TIMEOUT_NSEC(cparacfg)                        ((cparacfg)->cdns_timeout_nsec)
#define CPARACFG_LOG_LEVEL_TAB(cparacfg)                            ((cparacfg)->log_level_tab)

#define CPARACFG_DNS_CACHE_SWITCH(cparacfg)                         ((cparacfg)->dns_cache_switch)
#define CPARACFG_DNS_CACHE_EXPIRED_NSEC(cparacfg)                   ((cparacfg)->dns_cache_expired_nsec)

#define CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)               ((cparacfg)->high_precision_time_switch)

#define CPARACFG_CXFSNP_MAX_USED_RATIO(cparacfg)                    ((cparacfg)->cxfsnp_max_used_ratio)
#define CPARACFG_CXFSDN_MAX_USED_RATIO(cparacfg)                    ((cparacfg)->cxfsdn_max_used_ratio)

#define CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM(cparacfg)                ((cparacfg)->cxfsnp_try_retire_max_num)
#define CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM(cparacfg)               ((cparacfg)->cxfsnp_try_recycle_max_num)
#define CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH(cparacfg)               ((cparacfg)->cxfsnp_cache_in_mem_switch)
#define CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH(cparacfg)               ((cparacfg)->cxfsdn_cache_in_mem_switch)

#define CPARACFG_CXFSDN_CAMD_SWITCH(cparacfg)                       ((cparacfg)->cxfsdn_camd_switch)
#define CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE(cparacfg)                ((cparacfg)->cxfsdn_camd_mem_disk_size)

#define CPARACFG_CXFS_LRU_MODEL_SWITCH(cparacfg)                    ((cparacfg)->cxfs_lru_model_switch)
#define CPARACFG_CXFS_FIFO_MODEL_SWITCH(cparacfg)                   ((cparacfg)->cxfs_fifo_model_switch)

#define CPARACFG_CXFS_LRU_MODEL_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CXFS_LRU_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CXFS_FIFO_MODEL_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CXFS_FIFO_MODEL_SWITCH(cparacfg)))

#define CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH(cparacfg)                ((cparacfg)->cxfs_camd_overhead_switch)
#define CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH_STR(cparacfg)            (c_switch_to_str(CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH(cparacfg)))

#define CPARACFG_CXFS_CAMD_DISCARD_RATIO(cparacfg)                  ((cparacfg)->cxfs_camd_discard_ratio)

#define CPARACFG_CXFSNBD_DEVICE_NAME_CSTR(cparacfg)                 (&((cparacfg)->cxfsnbd_device_name_cstr))
#define CPARACFG_CXFSNBD_DEVICE_NAME_STR(cparacfg)                  ((char *)cstring_get_str(CPARACFG_CXFSNBD_DEVICE_NAME_CSTR(cparacfg)))
#define CPARACFG_CXFSNBD_DEVICE_SIZE(cparacfg)                      ((cparacfg)->cxfsnbd_device_size)
#define CPARACFG_CXFSNBD_BLOCK_SIZE(cparacfg)                       ((cparacfg)->cxfsnbd_block_size)
#define CPARACFG_CXFSNBD_TIMEOUT_NSEC(cparacfg)                     ((cparacfg)->cxfsnbd_timeout_nsec)

#define CPARACFG_CMON_CONHASH_SWITCH(cparacfg)                      ((cparacfg)->cmon_conhash_switch)
#define CPARACFG_CMON_CONHASH_REPLICAS(cparacfg)                    ((cparacfg)->cmon_conhash_replicas)

#define CPARACFG_CMON_MAGLEV_SWITCH(cparacfg)                       ((cparacfg)->cmon_maglev_switch)

#define CPARACFG_CMON_HOT_PATH_SWITCH(cparacfg)                     ((cparacfg)->cmon_hot_path_switch)

#define CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg)            ((cparacfg)->ngx_lua_output_blocking_lowat)
#define CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg)                   ((cparacfg)->ngx_epoll_timeout_msec)

#define CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg)                ((cparacfg)->ngx_http_req_num_per_loop)
#define CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)                ((cparacfg)->xfs_http_req_num_per_loop)

#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg)           (&((cparacfg)->ssl_certificate_file_name_cstr))
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg)           (&((cparacfg)->ssl_private_key_file_name_cstr))

#define CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)                      ((cparacfg)->tdns_resolve_switch)
#define CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC(cparacfg)                ((cparacfg)->tdns_resolve_timeout_nsec)

#define CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM(cparacfg)                 ((cparacfg)->camd_ssd_aio_req_max_num)
#define CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM(cparacfg)                ((cparacfg)->camd_sata_aio_req_max_num)
#define CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH(cparacfg)             ((cparacfg)->camd_sata_degrade_ssd_switch)

#define CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH(cparacfg)              ((cparacfg)->camd_ssd_upgrade_mem_switch)
#define CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH(cparacfg)             ((cparacfg)->camd_sata_upgrade_mem_switch)

#define CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH(cparacfg)              ((cparacfg)->camd_check_page_used_switch)

#define CPARACFG_CMC_TRY_RETIRE_MAX_NUM(cparacfg)                   ((cparacfg)->cmc_try_retire_max_num)
#define CPARACFG_CMC_TRY_RECYCLE_MAX_NUM(cparacfg)                  ((cparacfg)->cmc_try_recycle_max_num)
#define CPARACFG_CMC_SCAN_RETIRE_MAX_NUM(cparacfg)                  ((cparacfg)->cmc_scan_retire_max_num)

#define CPARACFG_CMC_FLOW_CONTROL_SWITCH(cparacfg)                  ((cparacfg)->cmc_flow_control_switch)
#define CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM(cparacfg)              ((cparacfg)->cmc_process_degrade_max_num)
#define CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM(cparacfg)                 ((cparacfg)->cmc_scan_degrade_max_num)

#define CPARACFG_CMC_FLOW_CONTROL_SWITCH_STR(cparacfg)              (c_switch_to_str(CPARACFG_CMC_FLOW_CONTROL_SWITCH(cparacfg)))

#define CPARACFG_CMC_DEGRADE_HI_RATIO(cparacfg)                     ((cparacfg)->cmc_degrade_hi_ratio)
#define CPARACFG_CMC_DEGRADE_MD_RATIO(cparacfg)                     ((cparacfg)->cmc_degrade_md_ratio)
#define CPARACFG_CMC_DEGRADE_LO_RATIO(cparacfg)                     ((cparacfg)->cmc_degrade_lo_ratio)

#define CPARACFG_CMC_LRU_MODEL_SWITCH(cparacfg)                     ((cparacfg)->cmc_lru_model_switch)
#define CPARACFG_CMC_FIFO_MODEL_SWITCH(cparacfg)                    ((cparacfg)->cmc_fifo_model_switch)

#define CPARACFG_CMC_LRU_MODEL_SWITCH_STR(cparacfg)                 (c_switch_to_str(CPARACFG_CMC_LRU_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CMC_FIFO_MODEL_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CMC_FIFO_MODEL_SWITCH(cparacfg)))

#define CPARACFG_CDC_TRY_RETIRE_MAX_NUM(cparacfg)                   ((cparacfg)->cdc_try_retire_max_num)
#define CPARACFG_CDC_TRY_RECYCLE_MAX_NUM(cparacfg)                  ((cparacfg)->cdc_try_recycle_max_num)
#define CPARACFG_CDC_SCAN_RETIRE_MAX_NUM(cparacfg)                  ((cparacfg)->cdc_scan_retire_max_num)

#define CPARACFG_CDC_READ_CACHE_SWITCH(cparacfg)                    ((cparacfg)->cdc_read_cache_switch)
#define CPARACFG_CDC_FLOW_CONTROL_SWITCH(cparacfg)                  ((cparacfg)->cdc_flow_control_switch)
#define CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM(cparacfg)              ((cparacfg)->cdc_process_degrade_max_num)
#define CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM(cparacfg)                 ((cparacfg)->cdc_scan_degrade_max_num)

#define CPARACFG_CDC_READ_CACHE_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CDC_READ_CACHE_SWITCH(cparacfg)))
#define CPARACFG_CDC_FLOW_CONTROL_SWITCH_STR(cparacfg)              (c_switch_to_str(CPARACFG_CDC_FLOW_CONTROL_SWITCH(cparacfg)))

#define CPARACFG_CDC_DEGRADE_HI_RATIO(cparacfg)                     ((cparacfg)->cdc_degrade_hi_ratio)
#define CPARACFG_CDC_DEGRADE_MD_RATIO(cparacfg)                     ((cparacfg)->cdc_degrade_md_ratio)
#define CPARACFG_CDC_DEGRADE_LO_RATIO(cparacfg)                     ((cparacfg)->cdc_degrade_lo_ratio)

#define CPARACFG_CDC_LRU_MODEL_SWITCH(cparacfg)                     ((cparacfg)->cdc_lru_model_switch)
#define CPARACFG_CDC_FIFO_MODEL_SWITCH(cparacfg)                    ((cparacfg)->cdc_fifo_model_switch)

#define CPARACFG_CDC_LRU_MODEL_SWITCH_STR(cparacfg)                 (c_switch_to_str(CPARACFG_CDC_LRU_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CDC_FIFO_MODEL_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CDC_FIFO_MODEL_SWITCH(cparacfg)))


//#define CPARACFG_CONN_KEEPALIVE_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CONN_KEEPALIVE_SWITCH(cparacfg)))
#define CPARACFG_HIGH_PRECISION_TIME_SWITCH_STR(cparacfg)           (c_switch_to_str(CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)))
#define CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH_STR(cparacfg)          (c_switch_to_str(CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(cparacfg)))

#define CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH_STR(cparacfg)           (c_switch_to_str(CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(cparacfg)))

#define CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH_STR(cparacfg)           (c_switch_to_str(CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH(cparacfg)))
#define CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH_STR(cparacfg)           (c_switch_to_str(CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH(cparacfg)))

#define CPARACFG_CXFSDN_CAMD_SWITCH_STR(cparacfg)                   (c_switch_to_str(CPARACFG_CXFSDN_CAMD_SWITCH(cparacfg)))

#define CPARACFG_CMON_CONHASH_SWITCH_STR(cparacfg)                  (c_switch_to_str(CPARACFG_CMON_CONHASH_SWITCH(cparacfg)))
#define CPARACFG_CMON_MAGLEV_SWITCH_STR(cparacfg)                   (c_switch_to_str(CPARACFG_CMON_MAGLEV_SWITCH(cparacfg)))

#define CPARACFG_CMON_HOT_PATH_SWITCH_STR(cparacfg)                 (c_switch_to_str(CPARACFG_CMON_HOT_PATH_SWITCH(cparacfg)))

#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_STR(cparacfg)            ((char *)cstring_get_str(CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg)))
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_STR(cparacfg)            ((char *)cstring_get_str(CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg)))

#define CPARACFG_TDNS_RESOLVE_SWITCH_STR(cparacfg)                  (c_switch_to_str(CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)))
#define CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH_STR(cparacfg)         (c_switch_to_str(CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH(cparacfg)))
#define CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH_STR(cparacfg)          (c_switch_to_str(CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH(cparacfg)))
#define CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH_STR(cparacfg)         (c_switch_to_str(CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH(cparacfg)))

#define CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH_STR(cparacfg)          (c_switch_to_str(CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH(cparacfg)))

#define CPARACFG_DNS_CACHE_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_DNS_CACHE_SWITCH(cparacfg)))

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
#define CPARACFG_PROC_CORE_ID_DEF                                CMPI_ERROR_CORE_ID

#define CPARACFG_TASK_REQ_THREAD_MAX_NUM_DEF                     512
#define CPARACFG_TASK_RSP_THREAD_MAX_NUM_DEF                     32
#define CPARACFG_CTHREAD_STACK_MAX_SIZE_DEF                      CTHREAD_STACK_MAX_SIZE_064K
#define CPARACFG_CTHREAD_STACK_GUARD_SIZE_DEF                    CTHREAD_STACK_GUARD_SIZE_004K

#define CPARACFG_TASK_SLOW_DOWN_MSEC_DEF                         1
#define CPARACFG_TASK_LIVE_NSEC_DEF                              180
#define CPARACFG_TASK_ZOMBIE_NSEC_DEF                            30

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
#define CPARACFG_CSOCKET_CNODE_NUM_DEF                           1

#define CPARACFG_FILE_LOG_MAX_RECORDS_DEF                        FILE_LOG_RECORDS_010K

#define CPARACFG_CEPOLL_EVENT_MAX_NUM_DEF                        1024

#define CPARACFG_SRV_ACCEPT_MAX_NUM_DEF                          256

#define CPARACFG_CONSOLE_TERM_SWITCH_DEF                         SWITCH_OFF

#define CPARACFG_CONN_TIMEOUT_NSEC_DEF                           20
#define CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP_DEF                    1024
#define CPARACFG_CDNS_TIMEOUT_NSEC_DEF                           3

#define CPARACFG_DNS_CACHE_SWITCH_DEF                            SWITCH_ON
#define CPARACFG_DNS_CACHE_EXPIRED_NSEC_DEF                      60

#define CPARACFG_HIGH_PRECISION_TIME_SWITCH_DEF                  SWITCH_OFF

#define CPARACFG_CXFSNP_MAX_USED_RATIO_DEF                       (0.999)
#define CPARACFG_CXFSDN_MAX_USED_RATIO_DEF                       (0.980)

#define CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM_DEF                   128
#define CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM_DEF                  512
#define CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH_DEF                  SWITCH_OFF
#define CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH_DEF                  SWITCH_OFF

#define CPARACFG_CXFSDN_CAMD_SWITCH_DEF                          SWITCH_OFF
#define CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE_DEF                   0

#define CPARACFG_CXFS_LRU_MODEL_SWITCH_DEF                       SWITCH_OFF
#define CPARACFG_CXFS_FIFO_MODEL_SWITCH_DEF                      SWITCH_ON

#define CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH_DEF                   SWITCH_OFF
#define CPARACFG_CXFS_CAMD_DISCARD_RATIO_DEF                     10 /*1/10*/

#define CPARACFG_CXFSNBD_DEVICE_NAME_CSTR_DEF                   ((uint8_t *)"/dev/nbd0")
#define CPARACFG_CXFSNBD_DEVICE_SIZE_DEF                         (128 << 20) /*128MB*/
#define CPARACFG_CXFSNBD_BLOCK_SIZE_DEF                          512 /*512B*/
#define CPARACFG_CXFSNBD_TIMEOUT_NSEC_DEF                        30

#define CPARACFG_CMON_CONHASH_SWITCH_DEF                         SWITCH_OFF
#define CPARACFG_CMON_CONHASH_REPLICAS_DEF                       160
#define CPARACFG_CMON_MAGLEV_SWITCH_DEF                          SWITCH_ON

#define CPARACFG_CMON_HOT_PATH_SWITCH_DEF                        SWITCH_ON

#define CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT_DEF               MEM_BUFF_32K
#define CPARACFG_NGX_EPOLL_TIMEOUT_MSEC_DEF                      0

#define CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP_DEF                   0 /*0 means handle all*/
#define CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP_DEF                   0 /*0 means handle all*/
#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR_DEF              ((uint8_t *)"certificate.pem")
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR_DEF              ((uint8_t *)"private_key.pem")

#define CPARACFG_TDNS_RESOLVE_SWITCH_DEF                         SWITCH_OFF
#define CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC_DEF                   30 /*30 seconds*/

#define CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM_DEF                    64
#define CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM_DEF                   64
#define CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH_DEF                SWITCH_ON

#define CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH_DEF                 SWITCH_ON
#define CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH_DEF                SWITCH_ON

#define CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH_DEF                 SWITCH_OFF

#define CPARACFG_CMC_TRY_RETIRE_MAX_NUM_DEF                      8
#define CPARACFG_CMC_TRY_RECYCLE_MAX_NUM_DEF                     128
#define CPARACFG_CMC_SCAN_RETIRE_MAX_NUM_DEF                     256

#define CPARACFG_CMC_FLOW_CONTROL_SWITCH_DEF                     SWITCH_OFF
#define CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM_DEF                 8
#define CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM_DEF                    256

#define CPARACFG_CMC_DEGRADE_HI_RATIO_DEF                        0.90
#define CPARACFG_CMC_DEGRADE_MD_RATIO_DEF                        0.85
#define CPARACFG_CMC_DEGRADE_LO_RATIO_DEF                        0.80

#define CPARACFG_CMC_LRU_MODEL_SWITCH_DEF                        SWITCH_ON
#define CPARACFG_CMC_FIFO_MODEL_SWITCH_DEF                       SWITCH_OFF

#define CPARACFG_CDC_TRY_RETIRE_MAX_NUM_DEF                      8
#define CPARACFG_CDC_TRY_RECYCLE_MAX_NUM_DEF                     128
#define CPARACFG_CDC_SCAN_RETIRE_MAX_NUM_DEF                     128

#define CPARACFG_CDC_READ_CACHE_SWITCH_DEF                       SWITCH_ON
#define CPARACFG_CDC_FLOW_CONTROL_SWITCH_DEF                     SWITCH_OFF
#define CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM_DEF                 8
#define CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM_DEF                    256

#define CPARACFG_CDC_LRU_MODEL_SWITCH_DEF                        SWITCH_ON
#define CPARACFG_CDC_FIFO_MODEL_SWITCH_DEF                       SWITCH_OFF

#define CPARACFG_CDC_DEGRADE_HI_RATIO_DEF                        0.90
#define CPARACFG_CDC_DEGRADE_MD_RATIO_DEF                        0.85
#define CPARACFG_CDC_DEGRADE_LO_RATIO_DEF                        0.80

#define CPARACFG_SET_DEFAULT(cparacfg, macro_name)  \
            macro_name(cparacfg)  = macro_name##_DEF

#define CPARACFG_SET_STR_DEFAULT(cparacfg, macro_name)  \
            cstring_init(macro_name(cparacfg), macro_name##_DEF)

/*------------------------------------------------- default value definition END -------------------------------------------------*/

#define    CPARACFG_DEFAULT_GET()                        (TASK_BRD_CPARACFG(task_brd_default_get()))

#define    CPARACFG_DEFAULT_SET(name, value)  do{CPARACFG_##name(CPARACFG_DEFAULT_GET()) = (value);}while(0)

#define    CPARACFG_DEFAULT_MAP(macro_name) \
                (NULL_PTR == CPARACFG_DEFAULT_GET() ? (macro_name##_DEF): macro_name(CPARACFG_DEFAULT_GET()))

#define    CPARACFG_DEFAULT_RAW_MAP(macro_name) \
                (macro_name(CPARACFG_DEFAULT_GET()))

#define    CPARACFG_DEFAULT_STR_MAP(macro_name) \
                (NULL_PTR == CPARACFG_DEFAULT_GET() ? (char *)(macro_name##_DEF): (char *)cstring_get_str(macro_name(CPARACFG_DEFAULT_GET())))

#define    PROC_CORE_ID                                  CPARACFG_DEFAULT_MAP(CPARACFG_PROC_CORE_ID)

#define    TASK_REQ_THREAD_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_TASK_REQ_THREAD_MAX_NUM)
#define    TASK_RSP_THREAD_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_TASK_RSP_THREAD_MAX_NUM)

#define    TASK_SLOW_DOWN_MSEC                           CPARACFG_DEFAULT_MAP(CPARACFG_TASK_SLOW_DOWN_MSEC)
#define    TASK_LIVE_NSEC                                CPARACFG_DEFAULT_MAP(CPARACFG_TASK_LIVE_NSEC)
#define    TASK_ZOMBIE_NSEC                              CPARACFG_DEFAULT_MAP(CPARACFG_TASK_ZOMBIE_NSEC)

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

#define    FILE_LOG_MAX_RECORDS                          CPARACFG_DEFAULT_MAP(CPARACFG_FILE_LOG_MAX_RECORDS)

#define    CEPOLL_EVENT_MAX_NUM                          CPARACFG_DEFAULT_MAP(CPARACFG_CEPOLL_EVENT_MAX_NUM)

#define    SRV_ACCEPT_MAX_NUM                            CPARACFG_DEFAULT_MAP(CPARACFG_SRV_ACCEPT_MAX_NUM)

#define    CONN_TIMEOUT_NSEC                             CPARACFG_DEFAULT_MAP(CPARACFG_CONN_TIMEOUT_NSEC)
#define    CONN_TIMEOUT_MAX_NUM_PER_LOOP                 CPARACFG_DEFAULT_MAP(CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP)
#define    CDNS_TIMEOUT_NSEC                             CPARACFG_DEFAULT_MAP(CPARACFG_CDNS_TIMEOUT_NSEC)

#define    DNS_CACHE_SWITCH                              CPARACFG_DEFAULT_MAP(CPARACFG_DNS_CACHE_SWITCH)
#define    DNS_CACHE_EXPIRED_NSEC                        CPARACFG_DEFAULT_MAP(CPARACFG_DNS_CACHE_EXPIRED_NSEC)

#define    HIGH_PRECISION_TIME_SWITCH                    CPARACFG_DEFAULT_MAP(CPARACFG_HIGH_PRECISION_TIME_SWITCH)

#define    CXFSNP_MAX_USED_RATIO                         CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNP_MAX_USED_RATIO)
#define    CXFSDN_MAX_USED_RATIO                         CPARACFG_DEFAULT_MAP(CPARACFG_CXFSDN_MAX_USED_RATIO)

#define    CXFSNP_TRY_RETIRE_MAX_NUM                     CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM)
#define    CXFSNP_TRY_RECYCLE_MAX_NUM                    CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM)
#define    CXFSNP_CACHE_IN_MEM_SWITCH                    CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH)
#define    CXFSDN_CACHE_IN_MEM_SWITCH                    CPARACFG_DEFAULT_MAP(CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH)

#define    CXFSDN_CAMD_SWITCH                            CPARACFG_DEFAULT_MAP(CPARACFG_CXFSDN_CAMD_SWITCH)
#define    CXFSDN_CAMD_MEM_DISK_SIZE                     CPARACFG_DEFAULT_MAP(CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE)

#define    CXFS_LRU_MODEL_SWITCH                         CPARACFG_DEFAULT_MAP(CPARACFG_CXFS_LRU_MODEL_SWITCH)
#define    CXFS_FIFO_MODEL_SWITCH                        CPARACFG_DEFAULT_MAP(CPARACFG_CXFS_FIFO_MODEL_SWITCH)

#define    CXFS_CAMD_OVERHEAD_SWITCH                     CPARACFG_DEFAULT_MAP(CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH)
#define    CXFS_CAMD_DISCARD_RATIO                       CPARACFG_DEFAULT_MAP(CPARACFG_CXFS_CAMD_DISCARD_RATIO)

#define    CXFSNBD_DEVICE_NAME                           CPARACFG_DEFAULT_STR_MAP(CPARACFG_CXFSNBD_DEVICE_NAME_CSTR)
#define    CXFSNBD_DEVICE_SIZE                           CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNBD_DEVICE_SIZE)
#define    CXFSNBD_BLOCK_SIZE                            CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNBD_BLOCK_SIZE)
#define    CXFSNBD_TIMEOUT_NSEC                          CPARACFG_DEFAULT_MAP(CPARACFG_CXFSNBD_TIMEOUT_NSEC)

#define    CMON_CONHASH_SWITCH                           CPARACFG_DEFAULT_MAP(CPARACFG_CMON_CONHASH_SWITCH)
#define    CMON_CONHASH_REPLICAS                         CPARACFG_DEFAULT_MAP(CPARACFG_CMON_CONHASH_REPLICAS)
#define    CMON_MAGLEV_SWITCH                            CPARACFG_DEFAULT_MAP(CPARACFG_CMON_MAGLEV_SWITCH)

#define    CMON_HOT_PATH_SWITCH                          CPARACFG_DEFAULT_MAP(CPARACFG_CMON_HOT_PATH_SWITCH)

#define    NGX_LUA_OUTPUT_BLOCKING_LOWAT                 CPARACFG_DEFAULT_MAP(CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT)
#define    NGX_EPOLL_TIMEOUT_MSEC                        CPARACFG_DEFAULT_MAP(CPARACFG_NGX_EPOLL_TIMEOUT_MSEC)

#define    NGX_HTTP_REQ_NUM_PER_LOOP                     CPARACFG_DEFAULT_MAP(CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP)
#define    XFS_HTTP_REQ_NUM_PER_LOOP                     CPARACFG_DEFAULT_MAP(CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP)

#define    SSL_CERTIFICATE_FILE_NAME                     CPARACFG_DEFAULT_STR_MAP(CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR)
#define    SSL_PRIVATE_KEY_FILE_NAME                     CPARACFG_DEFAULT_STR_MAP(CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR)

#define    TDNS_RESOLVE_SWITCH                           CPARACFG_DEFAULT_MAP(CPARACFG_TDNS_RESOLVE_SWITCH)
#define    TDNS_RESOLVE_TIMEOUT_NSEC                     CPARACFG_DEFAULT_MAP(CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC)

#define    CAMD_SSD_AIO_REQ_MAX_NUM                      CPARACFG_DEFAULT_MAP(CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM)
#define    CAMD_SATA_AIO_REQ_MAX_NUM                     CPARACFG_DEFAULT_MAP(CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM)

#define    CAMD_SSD_AIO_REQ_MAX_NUM_RAW                  CPARACFG_DEFAULT_RAW_MAP(CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM)
#define    CAMD_SATA_AIO_REQ_MAX_NUM_RAW                 CPARACFG_DEFAULT_RAW_MAP(CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM)
#define    CAMD_SATA_DEGRADE_SSD_SWITCH                  CPARACFG_DEFAULT_MAP(CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH)

#define    CAMD_SSD_UPGRADE_MEM_SWITCH                   CPARACFG_DEFAULT_MAP(CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH)
#define    CAMD_SATA_UPGRADE_MEM_SWITCH                  CPARACFG_DEFAULT_MAP(CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH)

#define    CAMD_CHECK_PAGE_USED_SWITCH                   CPARACFG_DEFAULT_MAP(CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH)

#define    CMC_TRY_RETIRE_MAX_NUM                        CPARACFG_DEFAULT_MAP(CPARACFG_CMC_TRY_RETIRE_MAX_NUM)
#define    CMC_TRY_RECYCLE_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_CMC_TRY_RECYCLE_MAX_NUM)
#define    CMC_SCAN_RETIRE_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_CMC_SCAN_RETIRE_MAX_NUM)

#define    CMC_FLOW_CONTROL_SWITCH                       CPARACFG_DEFAULT_MAP(CPARACFG_CMC_FLOW_CONTROL_SWITCH)
#define    CMC_PROCESS_DEGRADE_MAX_NUM                   CPARACFG_DEFAULT_MAP(CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM)
#define    CMC_SCAN_DEGRADE_MAX_NUM                      CPARACFG_DEFAULT_MAP(CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM)

#define    CMC_DEGRADE_HI_RATIO                          CPARACFG_DEFAULT_MAP(CPARACFG_CMC_DEGRADE_HI_RATIO)
#define    CMC_DEGRADE_MD_RATIO                          CPARACFG_DEFAULT_MAP(CPARACFG_CMC_DEGRADE_MD_RATIO)
#define    CMC_DEGRADE_LO_RATIO                          CPARACFG_DEFAULT_MAP(CPARACFG_CMC_DEGRADE_LO_RATIO)

#define    CMC_LRU_MODEL_SWITCH                          CPARACFG_DEFAULT_MAP(CPARACFG_CMC_LRU_MODEL_SWITCH)
#define    CMC_FIFO_MODEL_SWITCH                         CPARACFG_DEFAULT_MAP(CPARACFG_CMC_FIFO_MODEL_SWITCH)

#define    CDC_TRY_RETIRE_MAX_NUM                        CPARACFG_DEFAULT_MAP(CPARACFG_CDC_TRY_RETIRE_MAX_NUM)
#define    CDC_TRY_RECYCLE_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_CDC_TRY_RECYCLE_MAX_NUM)
#define    CDC_SCAN_RETIRE_MAX_NUM                       CPARACFG_DEFAULT_MAP(CPARACFG_CDC_SCAN_RETIRE_MAX_NUM)

#define    CDC_READ_CACHE_SWITCH                         CPARACFG_DEFAULT_MAP(CPARACFG_CDC_READ_CACHE_SWITCH)
#define    CDC_FLOW_CONTROL_SWITCH                       CPARACFG_DEFAULT_MAP(CPARACFG_CDC_FLOW_CONTROL_SWITCH)
#define    CDC_PROCESS_DEGRADE_MAX_NUM                   CPARACFG_DEFAULT_MAP(CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM)
#define    CDC_SCAN_DEGRADE_MAX_NUM                      CPARACFG_DEFAULT_MAP(CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM)

#define    CDC_DEGRADE_HI_RATIO                          CPARACFG_DEFAULT_MAP(CPARACFG_CDC_DEGRADE_HI_RATIO)
#define    CDC_DEGRADE_MD_RATIO                          CPARACFG_DEFAULT_MAP(CPARACFG_CDC_DEGRADE_MD_RATIO)
#define    CDC_DEGRADE_LO_RATIO                          CPARACFG_DEFAULT_MAP(CPARACFG_CDC_DEGRADE_LO_RATIO)

#define    CDC_LRU_MODEL_SWITCH                          CPARACFG_DEFAULT_MAP(CPARACFG_CDC_LRU_MODEL_SWITCH)
#define    CDC_FIFO_MODEL_SWITCH                         CPARACFG_DEFAULT_MAP(CPARACFG_CDC_FIFO_MODEL_SWITCH)

#endif/*_CPARACFG_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
