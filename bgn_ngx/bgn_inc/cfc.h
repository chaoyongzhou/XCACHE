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

typedef struct
{
    uint64_t        next_time_ms;

    uint32_t        io_hit_num;      /*io hit counter*/
    uint32_t        io_miss_num;     /*io miss counter*/

    REAL            io_hit_ratio;    /*io hit ratio*/
}CIOSTAT;

#define CIOSTAT_NTIME_MS(ciostat)               ((ciostat)->next_time_ms)
#define CIOSTAT_IO_HIT_NUM(ciostat)             ((ciostat)->io_hit_num)
#define CIOSTAT_IO_MISS_NUM(ciostat)            ((ciostat)->io_miss_num)
#define CIOSTAT_IO_HIT_RATIO(ciostat)           ((ciostat)->io_hit_ratio)

/*----------------------------------- flow control interface -----------------------------------*/

CFC *cfc_new();

EC_BOOL cfc_init(CFC *cfc);

EC_BOOL cfc_clean(CFC *cfc);

EC_BOOL cfc_free(CFC *cfc);

EC_BOOL cfc_inc_traffic(CFC *cfc, const uint64_t traffic_nbytes);

EC_BOOL cfc_calc_speed(CFC *cfc, const uint64_t cur_time_ms, const uint64_t interval_ms);

uint64_t cfc_get_speed(const CFC *cfc);

/*----------------------------------- io hit/miss stat interface -----------------------------------*/

EC_BOOL ciostat_init(CIOSTAT *ciostat);

EC_BOOL ciostat_clean(CIOSTAT *ciostat);

EC_BOOL ciostat_inc_io_hit(CIOSTAT *ciostat);

EC_BOOL ciostat_inc_io_miss(CIOSTAT *ciostat);

REAL ciostat_get_io_hit_ratio(const CIOSTAT *ciostat);

EC_BOOL ciostat_calc_io_ratio(CIOSTAT *ciostat, const uint64_t cur_time_ms, const uint64_t interval_ms);

#endif /*_CFC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

