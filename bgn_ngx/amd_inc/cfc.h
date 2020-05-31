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

#define CFC_DEGRADE_TRAFFIC_02MB                       (((uint64_t) 2) << 23) /* 4MBps*/
#define CFC_DEGRADE_TRAFFIC_04MB                       (((uint64_t) 4) << 23) /* 4MBps*/
#define CFC_DEGRADE_TRAFFIC_08MB                       (((uint64_t) 8) << 23) /* 8MBps*/
#define CFC_DEGRADE_TRAFFIC_12MB                       (((uint64_t)12) << 23) /*12MBps*/
#define CFC_DEGRADE_TRAFFIC_14MB                       (((uint64_t)14) << 23) /*14MBps*/
#define CFC_DEGRADE_TRAFFIC_16MB                       (((uint64_t)16) << 23) /*16MBps*/
#define CFC_DEGRADE_TRAFFIC_18MB                       (((uint64_t)18) << 23) /*18MBps*/
#define CFC_DEGRADE_TRAFFIC_20MB                       (((uint64_t)20) << 23) /*20MBps*/
#define CFC_DEGRADE_TRAFFIC_24MB                       (((uint64_t)24) << 23) /*24MBps*/
#define CFC_DEGRADE_TRAFFIC_28MB                       (((uint64_t)28) << 23) /*28MBps*/
#define CFC_DEGRADE_TRAFFIC_32MB                       (((uint64_t)32) << 23) /*32MBps*/
#define CFC_DEGRADE_TRAFFIC_36MB                       (((uint64_t)36) << 23) /*36MBps*/
#define CFC_DEGRADE_TRAFFIC_40MB                       (((uint64_t)40) << 23) /*40MBps*/


/*flow control*/
typedef struct
{
    uint64_t        next_time_ms;
    uint64_t        traffic_nbytes;
    uint64_t        traffic_speed;   /*bps*/
    uint64_t        traffic_speed_next; /*for punish traffic speed*/
    int64_t         punish_degrade_traffic_bps; /*is lg 0, must use degrade traffic bps*/
    UINT32          frequency_rate_contral;/*contral frequency rate*/

}CFC;

#define CFC_NTIME_MS(cfc)                       ((cfc)->next_time_ms)
#define CFC_TRAFFIC_NBYTES(cfc)                 ((cfc)->traffic_nbytes)
#define CFC_TRAFFIC_SPEED(cfc)                  ((cfc)->traffic_speed)
#define CFC_TRAFFIC_SPEED_NEXT(cfc)             ((cfc)->traffic_speed_next)
#define CFC_PUNISH_DEGRADE_TRAFFIC_BPS(cfc)     ((cfc)->punish_degrade_traffic_bps)
#define CFC_FREQUENCY_RATE_CONTRAL(cfc)         ((cfc)->frequency_rate_contral)

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

EC_BOOL cfc_calc_speed(CFC *cfc, /*CFC *own_cfc, */const uint64_t cur_time_ms, const uint64_t interval_ms);

uint64_t cfc_get_speed(const CFC *cfc);

int64_t cfc_get_punish_degrade_traffic_bps(const CFC *cfc);


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

