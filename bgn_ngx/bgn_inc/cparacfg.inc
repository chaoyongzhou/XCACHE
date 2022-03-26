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

#define CPARACFG_THIS_TCID(cparacfg)                                     ((cparacfg)->node[  0]->u.data_word)
#define CPARACFG_THIS_RANK(cparacfg)                                     ((cparacfg)->node[  1]->u.data_word)
#define CPARACFG_PROC_CORE_ID(cparacfg)                                  ((cparacfg)->node[  2]->u.data_word)
#define CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg)                       ((cparacfg)->node[  3]->u.data_word)
#define CPARACFG_TASK_RSP_THREAD_MAX_NUM(cparacfg)                       ((cparacfg)->node[  4]->u.data_word)
#define CPARACFG_CTHREAD_STACK_MAX_SIZE(cparacfg)                        ((cparacfg)->node[  5]->u.data_word)
#define CPARACFG_CTHREAD_STACK_GUARD_SIZE(cparacfg)                      ((cparacfg)->node[  6]->u.data_word)
#define CPARACFG_TASK_SLOW_DOWN_MSEC(cparacfg)                           ((cparacfg)->node[  7]->u.data_word)
#define CPARACFG_TASK_LIVE_NSEC(cparacfg)                                ((cparacfg)->node[  8]->u.data_word)
#define CPARACFG_TASK_ZOMBIE_NSEC(cparacfg)                              ((cparacfg)->node[  9]->u.data_word)
#define CPARACFG_CSOCKET_SO_SNDBUFF_SIZE(cparacfg)                       ((cparacfg)->node[ 10]->u.data_int)
#define CPARACFG_CSOCKET_SO_RCVBUFF_SIZE(cparacfg)                       ((cparacfg)->node[ 11]->u.data_int)
#define CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE(cparacfg)                      ((cparacfg)->node[ 12]->u.data_int)
#define CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE(cparacfg)                      ((cparacfg)->node[ 13]->u.data_int)
#define CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC(cparacfg)                      ((cparacfg)->node[ 14]->u.data_int)
#define CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC(cparacfg)                      ((cparacfg)->node[ 15]->u.data_int)
#define CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(cparacfg)                   ((cparacfg)->node[ 16]->u.data_switch)
#define CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC(cparacfg)                     ((cparacfg)->node[ 17]->u.data_int)
#define CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC(cparacfg)                    ((cparacfg)->node[ 18]->u.data_int)
#define CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES(cparacfg)                     ((cparacfg)->node[ 19]->u.data_int)
#define CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(cparacfg)                    ((cparacfg)->node[ 20]->u.data_switch)
#define CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE(cparacfg)                    ((cparacfg)->node[ 21]->u.data_word)
#define CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE(cparacfg)                    ((cparacfg)->node[ 22]->u.data_word)
#define CPARACFG_CSOCKET_CNODE_NUM(cparacfg)                             ((cparacfg)->node[ 23]->u.data_word)
#define CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC(cparacfg)                  ((cparacfg)->node[ 24]->u.data_word)
#define CPARACFG_FILE_LOG_MAX_RECORDS(cparacfg)                          ((cparacfg)->node[ 25]->u.data_word)
#define CPARACFG_CEPOLL_EVENT_MAX_NUM(cparacfg)                          ((cparacfg)->node[ 26]->u.data_word)
#define CPARACFG_SRV_ACCEPT_MAX_NUM(cparacfg)                            ((cparacfg)->node[ 27]->u.data_word)
#define CPARACFG_CONN_TIMEOUT_NSEC(cparacfg)                             ((cparacfg)->node[ 28]->u.data_word)
#define CPARACFG_CONN_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg)                 ((cparacfg)->node[ 29]->u.data_word)
#define CPARACFG_CDNS_TIMEOUT_NSEC(cparacfg)                             ((cparacfg)->node[ 30]->u.data_word)
#define CPARACFG_DNS_CACHE_SWITCH(cparacfg)                              ((cparacfg)->node[ 31]->u.data_switch)
#define CPARACFG_DNS_CACHE_EXPIRED_NSEC(cparacfg)                        ((cparacfg)->node[ 32]->u.data_word)
#define CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)                    ((cparacfg)->node[ 33]->u.data_switch)
#define CPARACFG_CXFSNP_MAX_USED_RATIO(cparacfg)                         ((cparacfg)->node[ 34]->u.data_real)
#define CPARACFG_CXFSDN_MAX_USED_RATIO(cparacfg)                         ((cparacfg)->node[ 35]->u.data_real)
#define CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM(cparacfg)                     ((cparacfg)->node[ 36]->u.data_word)
#define CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM(cparacfg)                    ((cparacfg)->node[ 37]->u.data_word)
#define CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH(cparacfg)                    ((cparacfg)->node[ 38]->u.data_switch)
#define CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH(cparacfg)                    ((cparacfg)->node[ 39]->u.data_switch)
#define CPARACFG_CXFSDN_CAMD_SWITCH(cparacfg)                            ((cparacfg)->node[ 40]->u.data_switch)
#define CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE(cparacfg)                     ((cparacfg)->node[ 41]->u.data_word)
#define CPARACFG_CXFS_LRU_MODEL_SWITCH(cparacfg)                         ((cparacfg)->node[ 42]->u.data_switch)
#define CPARACFG_CXFS_FIFO_MODEL_SWITCH(cparacfg)                        ((cparacfg)->node[ 43]->u.data_switch)
#define CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH(cparacfg)                     ((cparacfg)->node[ 44]->u.data_switch)
#define CPARACFG_CXFS_CAMD_DISCARD_RATIO(cparacfg)                       ((cparacfg)->node[ 45]->u.data_word)
#define CPARACFG_CXFSNBD_DEVICE_SIZE(cparacfg)                           ((cparacfg)->node[ 46]->u.data_word)
#define CPARACFG_CXFSNBD_BLOCK_SIZE(cparacfg)                            ((cparacfg)->node[ 47]->u.data_word)
#define CPARACFG_CXFSNBD_TIMEOUT_NSEC(cparacfg)                          ((cparacfg)->node[ 48]->u.data_word)
#define CPARACFG_CMON_CONHASH_SWITCH(cparacfg)                           ((cparacfg)->node[ 49]->u.data_switch)
#define CPARACFG_CMON_CONHASH_REPLICAS(cparacfg)                         ((cparacfg)->node[ 50]->u.data_u16)
#define CPARACFG_CMON_MAGLEV_SWITCH(cparacfg)                            ((cparacfg)->node[ 51]->u.data_switch)
#define CPARACFG_CMON_HOT_PATH_SWITCH(cparacfg)                          ((cparacfg)->node[ 52]->u.data_switch)
#define CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg)                 ((cparacfg)->node[ 53]->u.data_u32)
#define CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg)                        ((cparacfg)->node[ 54]->u.data_u32)
#define CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg)                     ((cparacfg)->node[ 55]->u.data_u32)
#define CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)                     ((cparacfg)->node[ 56]->u.data_u32)
#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg)                ((cparacfg)->node[ 57]->u.data_cstr)
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg)                ((cparacfg)->node[ 58]->u.data_cstr)
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR(cparacfg)        ((cparacfg)->node[ 59]->u.data_cstr)
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR(cparacfg)        ((cparacfg)->node[ 60]->u.data_cstr)
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR(cparacfg)           ((cparacfg)->node[ 61]->u.data_cstr)
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR(cparacfg)            ((cparacfg)->node[ 62]->u.data_cstr)
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR(cparacfg)     ((cparacfg)->node[ 63]->u.data_cstr)
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC(cparacfg)       ((cparacfg)->node[ 64]->u.data_word)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE(cparacfg)         ((cparacfg)->node[ 65]->u.data_u32)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE(cparacfg)         ((cparacfg)->node[ 66]->u.data_u32)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM(cparacfg)    ((cparacfg)->node[ 67]->u.data_u32)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM(cparacfg)     ((cparacfg)->node[ 68]->u.data_u32)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM(cparacfg)     ((cparacfg)->node[ 69]->u.data_u32)
#define CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)                           ((cparacfg)->node[ 70]->u.data_switch)
#define CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC(cparacfg)                     ((cparacfg)->node[ 71]->u.data_word)
#define CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM(cparacfg)                      ((cparacfg)->node[ 72]->u.data_word)
#define CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM(cparacfg)                     ((cparacfg)->node[ 73]->u.data_word)
#define CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH(cparacfg)                  ((cparacfg)->node[ 74]->u.data_switch)
#define CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH(cparacfg)                   ((cparacfg)->node[ 75]->u.data_switch)
#define CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH(cparacfg)                  ((cparacfg)->node[ 76]->u.data_switch)
#define CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH(cparacfg)                   ((cparacfg)->node[ 77]->u.data_switch)
#define CPARACFG_CMC_TRY_RETIRE_MAX_NUM(cparacfg)                        ((cparacfg)->node[ 78]->u.data_word)
#define CPARACFG_CMC_TRY_RECYCLE_MAX_NUM(cparacfg)                       ((cparacfg)->node[ 79]->u.data_word)
#define CPARACFG_CMC_SCAN_RETIRE_MAX_NUM(cparacfg)                       ((cparacfg)->node[ 80]->u.data_word)
#define CPARACFG_CMC_FLOW_CONTROL_SWITCH(cparacfg)                       ((cparacfg)->node[ 81]->u.data_switch)
#define CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM(cparacfg)                   ((cparacfg)->node[ 82]->u.data_word)
#define CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM(cparacfg)                      ((cparacfg)->node[ 83]->u.data_word)
#define CPARACFG_CMC_DEGRADE_HI_RATIO(cparacfg)                          ((cparacfg)->node[ 84]->u.data_real)
#define CPARACFG_CMC_DEGRADE_MD_RATIO(cparacfg)                          ((cparacfg)->node[ 85]->u.data_real)
#define CPARACFG_CMC_DEGRADE_LO_RATIO(cparacfg)                          ((cparacfg)->node[ 86]->u.data_real)
#define CPARACFG_CMC_LRU_MODEL_SWITCH(cparacfg)                          ((cparacfg)->node[ 87]->u.data_switch)
#define CPARACFG_CMC_FIFO_MODEL_SWITCH(cparacfg)                         ((cparacfg)->node[ 88]->u.data_switch)
#define CPARACFG_CDC_TRY_RETIRE_MAX_NUM(cparacfg)                        ((cparacfg)->node[ 89]->u.data_word)
#define CPARACFG_CDC_TRY_RECYCLE_MAX_NUM(cparacfg)                       ((cparacfg)->node[ 90]->u.data_word)
#define CPARACFG_CDC_SCAN_RETIRE_MAX_NUM(cparacfg)                       ((cparacfg)->node[ 91]->u.data_word)
#define CPARACFG_CDC_READ_CACHE_SWITCH(cparacfg)                         ((cparacfg)->node[ 92]->u.data_switch)
#define CPARACFG_CDC_FLOW_CONTROL_SWITCH(cparacfg)                       ((cparacfg)->node[ 93]->u.data_switch)
#define CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM(cparacfg)                   ((cparacfg)->node[ 94]->u.data_word)
#define CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM(cparacfg)                      ((cparacfg)->node[ 95]->u.data_word)
#define CPARACFG_CDC_DEGRADE_HI_RATIO(cparacfg)                          ((cparacfg)->node[ 96]->u.data_real)
#define CPARACFG_CDC_DEGRADE_MD_RATIO(cparacfg)                          ((cparacfg)->node[ 97]->u.data_real)
#define CPARACFG_CDC_DEGRADE_LO_RATIO(cparacfg)                          ((cparacfg)->node[ 98]->u.data_real)
#define CPARACFG_CDC_LRU_MODEL_SWITCH(cparacfg)                          ((cparacfg)->node[ 99]->u.data_switch)
#define CPARACFG_CDC_FIFO_MODEL_SWITCH(cparacfg)                         ((cparacfg)->node[100]->u.data_switch)

#define CPARACFG_SSL_CERTIFICATE_FILE_NAME_STR(cparacfg)                 ((char *)cstring_get_str(CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg)))
#define CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_STR(cparacfg)                 ((char *)cstring_get_str(CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg)))
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_SERVER_STR(cparacfg)         ((char *)cstring_get_str(CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR(cparacfg)))
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_STR(cparacfg)         ((char *)cstring_get_str(CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR(cparacfg)))
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_URI_STR(cparacfg)            ((char *)cstring_get_str(CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR(cparacfg)))
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_OP_STR(cparacfg)             ((char *)cstring_get_str(CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR(cparacfg)))
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_STR(cparacfg)      ((char *)cstring_get_str(CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR(cparacfg)))

#define CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(cparacfg)))
#define CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(cparacfg)))
#define CPARACFG_HIGH_PRECISION_TIME_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)))
#define CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH(cparacfg)))
#define CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH_STR(cparacfg)                (c_switch_to_str(CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH(cparacfg)))
#define CPARACFG_CXFSDN_CAMD_SWITCH_STR(cparacfg)                        (c_switch_to_str(CPARACFG_CXFSDN_CAMD_SWITCH(cparacfg)))
#define CPARACFG_CXFS_LRU_MODEL_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CXFS_LRU_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CXFS_FIFO_MODEL_SWITCH_STR(cparacfg)                    (c_switch_to_str(CPARACFG_CXFS_FIFO_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH_STR(cparacfg)                 (c_switch_to_str(CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH(cparacfg)))
#define CPARACFG_CMON_MAGLEV_SWITCH_STR(cparacfg)                        (c_switch_to_str(CPARACFG_CMON_MAGLEV_SWITCH(cparacfg)))
#define CPARACFG_CMON_HOT_PATH_SWITCH_STR(cparacfg)                      (c_switch_to_str(CPARACFG_CMON_HOT_PATH_SWITCH(cparacfg)))
#define CPARACFG_TDNS_RESOLVE_SWITCH_STR(cparacfg)                       (c_switch_to_str(CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)))
#define CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH_STR(cparacfg)              (c_switch_to_str(CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH(cparacfg)))
#define CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH(cparacfg)))
#define CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH_STR(cparacfg)              (c_switch_to_str(CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH(cparacfg)))
#define CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH_STR(cparacfg)               (c_switch_to_str(CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH(cparacfg)))
#define CPARACFG_CMC_LRU_MODEL_SWITCH_STR(cparacfg)                      (c_switch_to_str(CPARACFG_CMC_LRU_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CMC_FIFO_MODEL_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CMC_FIFO_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CDC_READ_CACHE_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CDC_READ_CACHE_SWITCH(cparacfg)))
#define CPARACFG_CDC_FLOW_CONTROL_SWITCH_STR(cparacfg)                   (c_switch_to_str(CPARACFG_CDC_FLOW_CONTROL_SWITCH(cparacfg)))
#define CPARACFG_CDC_LRU_MODEL_SWITCH_STR(cparacfg)                      (c_switch_to_str(CPARACFG_CDC_LRU_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CDC_FIFO_MODEL_SWITCH_STR(cparacfg)                     (c_switch_to_str(CPARACFG_CDC_FIFO_MODEL_SWITCH(cparacfg)))
#define CPARACFG_CMON_CONHASH_SWITCH_STR(cparacfg)                       (c_switch_to_str(CPARACFG_CMON_CONHASH_SWITCH(cparacfg)))
#define CPARACFG_DNS_CACHE_SWITCH_STR(cparacfg)                          (c_switch_to_str(CPARACFG_DNS_CACHE_SWITCH(cparacfg)))

#define CPARACFG_DEFAULT_GET()                                           (TASK_BRD_CPARACFG(task_brd_default_get()))

#define THIS_TCID                                                        CPARACFG_THIS_TCID(CPARACFG_DEFAULT_GET())
#define THIS_RANK                                                        CPARACFG_THIS_RANK(CPARACFG_DEFAULT_GET())
#define PROC_CORE_ID                                                     CPARACFG_PROC_CORE_ID(CPARACFG_DEFAULT_GET())
#define TASK_REQ_THREAD_MAX_NUM                                          CPARACFG_TASK_REQ_THREAD_MAX_NUM(CPARACFG_DEFAULT_GET())
#define TASK_RSP_THREAD_MAX_NUM                                          CPARACFG_TASK_RSP_THREAD_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CTHREAD_STACK_MAX_SIZE                                           CPARACFG_CTHREAD_STACK_MAX_SIZE(CPARACFG_DEFAULT_GET())
#define CTHREAD_STACK_GUARD_SIZE                                         CPARACFG_CTHREAD_STACK_GUARD_SIZE(CPARACFG_DEFAULT_GET())
#define TASK_SLOW_DOWN_MSEC                                              CPARACFG_TASK_SLOW_DOWN_MSEC(CPARACFG_DEFAULT_GET())
#define TASK_LIVE_NSEC                                                   CPARACFG_TASK_LIVE_NSEC(CPARACFG_DEFAULT_GET())
#define TASK_ZOMBIE_NSEC                                                 CPARACFG_TASK_ZOMBIE_NSEC(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_SNDBUFF_SIZE                                          CPARACFG_CSOCKET_SO_SNDBUFF_SIZE(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_RCVBUFF_SIZE                                          CPARACFG_CSOCKET_SO_RCVBUFF_SIZE(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_SNDLOWAT_SIZE                                         CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_RCVLOWAT_SIZE                                         CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_SNDTIMEO_NSEC                                         CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_RCVTIMEO_NSEC                                         CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC(CPARACFG_DEFAULT_GET())
#define CSOCKET_SO_KEEPALIVE_SWITCH                                      CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(CPARACFG_DEFAULT_GET())
#define CSOCKET_TCP_KEEPIDLE_NSEC                                        CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC(CPARACFG_DEFAULT_GET())
#define CSOCKET_TCP_KEEPINTVL_NSEC                                       CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC(CPARACFG_DEFAULT_GET())
#define CSOCKET_TCP_KEEPCNT_TIMES                                        CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES(CPARACFG_DEFAULT_GET())
#define CSOCKET_UNIX_DOMAIN_SWITCH                                       CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(CPARACFG_DEFAULT_GET())
#define CSOCKET_SEND_ONCE_MAX_SIZE                                       CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE(CPARACFG_DEFAULT_GET())
#define CSOCKET_RECV_ONCE_MAX_SIZE                                       CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE(CPARACFG_DEFAULT_GET())
#define CSOCKET_CNODE_NUM                                                CPARACFG_CSOCKET_CNODE_NUM(CPARACFG_DEFAULT_GET())
#define CSOCKET_HEARTBEAT_INTVL_NSEC                                     CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC(CPARACFG_DEFAULT_GET())
#define FILE_LOG_MAX_RECORDS                                             CPARACFG_FILE_LOG_MAX_RECORDS(CPARACFG_DEFAULT_GET())
#define CEPOLL_EVENT_MAX_NUM                                             CPARACFG_CEPOLL_EVENT_MAX_NUM(CPARACFG_DEFAULT_GET())
#define SRV_ACCEPT_MAX_NUM                                               CPARACFG_SRV_ACCEPT_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CONN_TIMEOUT_NSEC                                                CPARACFG_CONN_TIMEOUT_NSEC(CPARACFG_DEFAULT_GET())
#define CONN_TIMEOUT_MAX_NUM_PER_LOOP                                    CPARACFG_CONN_TIMEOUT_MAX_NUM_PER_LOOP(CPARACFG_DEFAULT_GET())
#define CDNS_TIMEOUT_NSEC                                                CPARACFG_CDNS_TIMEOUT_NSEC(CPARACFG_DEFAULT_GET())
#define DNS_CACHE_SWITCH                                                 CPARACFG_DNS_CACHE_SWITCH(CPARACFG_DEFAULT_GET())
#define DNS_CACHE_EXPIRED_NSEC                                           CPARACFG_DNS_CACHE_EXPIRED_NSEC(CPARACFG_DEFAULT_GET())
#define HIGH_PRECISION_TIME_SWITCH                                       CPARACFG_HIGH_PRECISION_TIME_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFSNP_MAX_USED_RATIO                                            CPARACFG_CXFSNP_MAX_USED_RATIO(CPARACFG_DEFAULT_GET())
#define CXFSDN_MAX_USED_RATIO                                            CPARACFG_CXFSDN_MAX_USED_RATIO(CPARACFG_DEFAULT_GET())
#define CXFSNP_TRY_RETIRE_MAX_NUM                                        CPARACFG_CXFSNP_TRY_RETIRE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CXFSNP_TRY_RECYCLE_MAX_NUM                                       CPARACFG_CXFSNP_TRY_RECYCLE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CXFSNP_CACHE_IN_MEM_SWITCH                                       CPARACFG_CXFSNP_CACHE_IN_MEM_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFSDN_CACHE_IN_MEM_SWITCH                                       CPARACFG_CXFSDN_CACHE_IN_MEM_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFSDN_CAMD_SWITCH                                               CPARACFG_CXFSDN_CAMD_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFSDN_CAMD_MEM_DISK_SIZE                                        CPARACFG_CXFSDN_CAMD_MEM_DISK_SIZE(CPARACFG_DEFAULT_GET())
#define CXFS_LRU_MODEL_SWITCH                                            CPARACFG_CXFS_LRU_MODEL_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFS_FIFO_MODEL_SWITCH                                           CPARACFG_CXFS_FIFO_MODEL_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFS_CAMD_OVERHEAD_SWITCH                                        CPARACFG_CXFS_CAMD_OVERHEAD_SWITCH(CPARACFG_DEFAULT_GET())
#define CXFS_CAMD_DISCARD_RATIO                                          CPARACFG_CXFS_CAMD_DISCARD_RATIO(CPARACFG_DEFAULT_GET())
#define CXFSNBD_DEVICE_SIZE                                              CPARACFG_CXFSNBD_DEVICE_SIZE(CPARACFG_DEFAULT_GET())
#define CXFSNBD_BLOCK_SIZE                                               CPARACFG_CXFSNBD_BLOCK_SIZE(CPARACFG_DEFAULT_GET())
#define CXFSNBD_TIMEOUT_NSEC                                             CPARACFG_CXFSNBD_TIMEOUT_NSEC(CPARACFG_DEFAULT_GET())
#define CMON_CONHASH_SWITCH                                              CPARACFG_CMON_CONHASH_SWITCH(CPARACFG_DEFAULT_GET())
#define CMON_CONHASH_REPLICAS                                            CPARACFG_CMON_CONHASH_REPLICAS(CPARACFG_DEFAULT_GET())
#define CMON_MAGLEV_SWITCH                                               CPARACFG_CMON_MAGLEV_SWITCH(CPARACFG_DEFAULT_GET())
#define CMON_HOT_PATH_SWITCH                                             CPARACFG_CMON_HOT_PATH_SWITCH(CPARACFG_DEFAULT_GET())
#define NGX_LUA_OUTPUT_BLOCKING_LOWAT                                    CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(CPARACFG_DEFAULT_GET())
#define NGX_EPOLL_TIMEOUT_MSEC                                           CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(CPARACFG_DEFAULT_GET())
#define NGX_HTTP_REQ_NUM_PER_LOOP                                        CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(CPARACFG_DEFAULT_GET())
#define XFS_HTTP_REQ_NUM_PER_LOOP                                        CPARACFG_XFS_HTTP_REQ_NUM_PER_LOOP(CPARACFG_DEFAULT_GET())
#define SSL_CERTIFICATE_FILE_NAME_CSTR                                   CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(CPARACFG_DEFAULT_GET())
#define SSL_CERTIFICATE_FILE_NAME                                        ((char *)cstring_get_str(SSL_CERTIFICATE_FILE_NAME_CSTR))
#define SSL_PRIVATE_KEY_FILE_NAME_CSTR                                   CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(CPARACFG_DEFAULT_GET())
#define SSL_PRIVATE_KEY_FILE_NAME                                        ((char *)cstring_get_str(SSL_PRIVATE_KEY_FILE_NAME_CSTR))
#define CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR                           CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_HTTP_REQ_SERVER                                ((char *)cstring_get_str(CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR))
#define CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR                           CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN                                ((char *)cstring_get_str(CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR))
#define CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR                              CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_HTTP_REQ_URI                                   ((char *)cstring_get_str(CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR))
#define CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR                               CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_HTTP_REQ_OP                                    ((char *)cstring_get_str(CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR))
#define CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR                        CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN                             ((char *)cstring_get_str(CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR))
#define CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC                          CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE                            CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE                            CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM                       CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM                        CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM                        CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM(CPARACFG_DEFAULT_GET())
#define TDNS_RESOLVE_SWITCH                                              CPARACFG_TDNS_RESOLVE_SWITCH(CPARACFG_DEFAULT_GET())
#define TDNS_RESOLVE_TIMEOUT_NSEC                                        CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC(CPARACFG_DEFAULT_GET())
#define CAMD_SSD_AIO_REQ_MAX_NUM                                         CPARACFG_CAMD_SSD_AIO_REQ_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CAMD_SATA_AIO_REQ_MAX_NUM                                        CPARACFG_CAMD_SATA_AIO_REQ_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CAMD_SATA_DEGRADE_SSD_SWITCH                                     CPARACFG_CAMD_SATA_DEGRADE_SSD_SWITCH(CPARACFG_DEFAULT_GET())
#define CAMD_SSD_UPGRADE_MEM_SWITCH                                      CPARACFG_CAMD_SSD_UPGRADE_MEM_SWITCH(CPARACFG_DEFAULT_GET())
#define CAMD_SATA_UPGRADE_MEM_SWITCH                                     CPARACFG_CAMD_SATA_UPGRADE_MEM_SWITCH(CPARACFG_DEFAULT_GET())
#define CAMD_CHECK_PAGE_USED_SWITCH                                      CPARACFG_CAMD_CHECK_PAGE_USED_SWITCH(CPARACFG_DEFAULT_GET())
#define CMC_TRY_RETIRE_MAX_NUM                                           CPARACFG_CMC_TRY_RETIRE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CMC_TRY_RECYCLE_MAX_NUM                                          CPARACFG_CMC_TRY_RECYCLE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CMC_SCAN_RETIRE_MAX_NUM                                          CPARACFG_CMC_SCAN_RETIRE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CMC_FLOW_CONTROL_SWITCH                                          CPARACFG_CMC_FLOW_CONTROL_SWITCH(CPARACFG_DEFAULT_GET())
#define CMC_PROCESS_DEGRADE_MAX_NUM                                      CPARACFG_CMC_PROCESS_DEGRADE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CMC_SCAN_DEGRADE_MAX_NUM                                         CPARACFG_CMC_SCAN_DEGRADE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CMC_DEGRADE_HI_RATIO                                             CPARACFG_CMC_DEGRADE_HI_RATIO(CPARACFG_DEFAULT_GET())
#define CMC_DEGRADE_MD_RATIO                                             CPARACFG_CMC_DEGRADE_MD_RATIO(CPARACFG_DEFAULT_GET())
#define CMC_DEGRADE_LO_RATIO                                             CPARACFG_CMC_DEGRADE_LO_RATIO(CPARACFG_DEFAULT_GET())
#define CMC_LRU_MODEL_SWITCH                                             CPARACFG_CMC_LRU_MODEL_SWITCH(CPARACFG_DEFAULT_GET())
#define CMC_FIFO_MODEL_SWITCH                                            CPARACFG_CMC_FIFO_MODEL_SWITCH(CPARACFG_DEFAULT_GET())
#define CDC_TRY_RETIRE_MAX_NUM                                           CPARACFG_CDC_TRY_RETIRE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CDC_TRY_RECYCLE_MAX_NUM                                          CPARACFG_CDC_TRY_RECYCLE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CDC_SCAN_RETIRE_MAX_NUM                                          CPARACFG_CDC_SCAN_RETIRE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CDC_READ_CACHE_SWITCH                                            CPARACFG_CDC_READ_CACHE_SWITCH(CPARACFG_DEFAULT_GET())
#define CDC_FLOW_CONTROL_SWITCH                                          CPARACFG_CDC_FLOW_CONTROL_SWITCH(CPARACFG_DEFAULT_GET())
#define CDC_PROCESS_DEGRADE_MAX_NUM                                      CPARACFG_CDC_PROCESS_DEGRADE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CDC_SCAN_DEGRADE_MAX_NUM                                         CPARACFG_CDC_SCAN_DEGRADE_MAX_NUM(CPARACFG_DEFAULT_GET())
#define CDC_DEGRADE_HI_RATIO                                             CPARACFG_CDC_DEGRADE_HI_RATIO(CPARACFG_DEFAULT_GET())
#define CDC_DEGRADE_MD_RATIO                                             CPARACFG_CDC_DEGRADE_MD_RATIO(CPARACFG_DEFAULT_GET())
#define CDC_DEGRADE_LO_RATIO                                             CPARACFG_CDC_DEGRADE_LO_RATIO(CPARACFG_DEFAULT_GET())
#define CDC_LRU_MODEL_SWITCH                                             CPARACFG_CDC_LRU_MODEL_SWITCH(CPARACFG_DEFAULT_GET())
#define CDC_FIFO_MODEL_SWITCH                                            CPARACFG_CDC_FIFO_MODEL_SWITCH(CPARACFG_DEFAULT_GET())

typedef struct
{
    const char              *macro_name;
    const char              *data_type;
    union
    {
        int                 data_int;
        uint8_t             data_u8;
        uint16_t            data_u16;
        uint32_t            data_u32;
        uint64_t            data_u64;
        UINT32              data_word;
        UINT32              data_switch;
        REAL                data_real;
        CSTRING            *data_cstr;
    }u;
}CPARACFG_NODE;

#define CPARACFG_NODE_MACRO_NAME(cparacfg_node)             ((cparacfg_node)->macro_name)
#define CPARACFG_NODE_TYPE_NAME(cparacfg_node)              ((cparacfg_node)->data_type)
#define CPARACFG_NODE_DATA_INT(cparacfg_node)               ((cparacfg_node)->u.data_int)
#define CPARACFG_NODE_DATA_U8(cparacfg_node)                ((cparacfg_node)->u.data_u8)
#define CPARACFG_NODE_DATA_U16(cparacfg_node)               ((cparacfg_node)->u.data_u16)
#define CPARACFG_NODE_DATA_U32(cparacfg_node)               ((cparacfg_node)->u.data_u32)
#define CPARACFG_NODE_DATA_U64(cparacfg_node)               ((cparacfg_node)->u.data_u64)
#define CPARACFG_NODE_DATA_WORD(cparacfg_node)              ((cparacfg_node)->u.data_word)
#define CPARACFG_NODE_DATA_SWITCH(cparacfg_node)            ((cparacfg_node)->u.data_switch)
#define CPARACFG_NODE_DATA_REAL(cparacfg_node)              ((cparacfg_node)->u.data_real)
#define CPARACFG_NODE_DATA_CSTR(cparacfg_node)              ((cparacfg_node)->u.data_cstr)

#define CPARACFG_NODE_MAX_NUM   256
typedef struct
{
    CPARACFG_NODE       *node[ CPARACFG_NODE_MAX_NUM ];
    UINT32               log_level_tab[ SEC_NONE_END ] ;

}CPARACFG;

#define CPARACFG_NODE(cparacfg, idx)                        ((cparacfg)->node[ (idx) ])
#define CPARACFG_LOG_LEVEL_TAB(cparacfg)                    ((cparacfg)->log_level_tab)


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
#define CPARACFG_THIS_TCID_DEF                                   CMPI_ERROR_TCID
#define CPARACFG_THIS_RANK_DEF                                   CMPI_ERROR_RANK
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
#define CPARACFG_CONN_TIMEOUT_MAX_NUM_PER_LOOP_DEF               1024
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

#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_SERVER_CSTR_DEF      ((uint8_t *)"127.0.0.1:80")
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN_CSTR_DEF      ((uint8_t *)"www.logagent.com")
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_URI_CSTR_DEF         ((uint8_t *)"/logs")
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_OP_CSTR_DEF          ((uint8_t *)"log")
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN_CSTR_DEF   ((uint8_t *)"4d0c1b2513cb82263814e10bf2f136ed")
#define CPARACFG_CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC_DEF     15
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE_DEF       ((uint32_t)( 4 << 10))
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE_DEF       ((uint32_t)(64 << 10))
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM_DEF  ((uint32_t)1024)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM_DEF   ((uint32_t)16)
#define CPARACFG_CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM_DEF   ((uint32_t)256)

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

/*------------------------------------------------- default value definition END -------------------------------------------------*/


#endif/*_CPARACFG_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
