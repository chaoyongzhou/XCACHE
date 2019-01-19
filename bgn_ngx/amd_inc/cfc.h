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

#ifndef _CFC_H
#define _CFC_H

#include "type.h"
#include "mm.h"
#include "log.h"

/*flow control*/
typedef struct
{
    uint64_t        next_time_ms;
    uint64_t        traffic_nbytes;
    uint64_t        traffic_speed;   /*bps*/
}CFC;

#define CFC_NTIME_MS(cfc)                       ((cfc)->next_time_ms)
#define CFC_TRAFFIC_NBYTES(cfc)                 ((cfc)->traffic_nbytes)
#define CFC_TRAFFIC_SPEED(cfc)                  ((cfc)->traffic_speed)



EC_BOOL cfc_init(CFC *cfc);

EC_BOOL cfc_clean(CFC *cfc);

EC_BOOL cfc_inc_traffic(CFC *cfc, const uint64_t traffic_nbytes);

EC_BOOL cfc_calc_speed(CFC *cfc, const uint64_t cur_time_ms, const uint64_t interval_ms);

uint64_t cfc_get_speed(const CFC *cfc);

#endif /*_CFC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

