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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "cfc.h"

/*----------------------------------- flow control interface -----------------------------------*/
EC_BOOL cfc_init(CFC *cfc)
{
    CFC_NTIME_MS(cfc)       = 0;
    CFC_TRAFFIC_NBYTES(cfc) = 0;
    CFC_TRAFFIC_SPEED(cfc)  = 0;

    return (EC_TRUE);
}

EC_BOOL cfc_clean(CFC *cfc)
{
    CFC_NTIME_MS(cfc)       = 0;
    CFC_TRAFFIC_NBYTES(cfc) = 0;
    CFC_TRAFFIC_SPEED(cfc)  = 0;

    return (EC_TRUE);
}

EC_BOOL cfc_inc_traffic(CFC *cfc, const uint64_t traffic_nbytes)
{
    CFC_TRAFFIC_NBYTES(cfc) += traffic_nbytes;
    return (EC_TRUE);
}

EC_BOOL cfc_calc_speed(CFC *cfc, const uint64_t cur_time_ms, const uint64_t interval_ms)
{
    if(cur_time_ms >= CFC_NTIME_MS(cfc) + interval_ms)
    {
        uint64_t    elapsed_ms;

        elapsed_ms = (cur_time_ms - CFC_NTIME_MS(cfc));

        CFC_TRAFFIC_SPEED(cfc)  = (CFC_TRAFFIC_NBYTES(cfc) * 8 * 1000) / (elapsed_ms);
        CFC_TRAFFIC_NBYTES(cfc) = 0;
        CFC_NTIME_MS(cfc)       = cur_time_ms + interval_ms;
    }

    return (EC_TRUE);
}

uint64_t cfc_get_speed(const CFC *cfc)
{
    return CFC_TRAFFIC_SPEED(cfc);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
