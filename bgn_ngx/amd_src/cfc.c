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
CFC *cfc_new()
{
    CFC *cfc;

    alloc_static_mem(MM_CFC, &cfc, LOC_CFC_0001);
    if(NULL_PTR == cfc)
    {
        dbg_log(SEC_0208_CFC, 0)(LOGSTDOUT, "error:cfc_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    cfc_init(cfc);
    return (cfc);
}

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

EC_BOOL cfc_free(CFC *cfc)
{
    if(NULL_PTR != cfc)
    {
        cfc_clean(cfc);
        free_static_mem(MM_CFC, cfc, LOC_CFC_0002);
    }
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
        CFC_TRAFFIC_NBYTES(cfc) = 0; /*clean up*/
        CFC_NTIME_MS(cfc)       = cur_time_ms + interval_ms;
    }

    return (EC_TRUE);
}

uint64_t cfc_get_speed(const CFC *cfc)
{
    return CFC_TRAFFIC_SPEED(cfc);
}

EC_BOOL ciostat_init(CIOSTAT *ciostat)
{
    CIOSTAT_NTIME_MS(ciostat)       = 0;

    CIOSTAT_IO_HIT_NUM(ciostat)     = 0;
    CIOSTAT_IO_MISS_NUM(ciostat)    = 0;

    CIOSTAT_IO_HIT_RATIO(ciostat)   = 0.0;

    return (EC_TRUE);
}

EC_BOOL ciostat_clean(CIOSTAT *ciostat)
{
    CIOSTAT_NTIME_MS(ciostat)       = 0;

    CIOSTAT_IO_HIT_NUM(ciostat)     = 0;
    CIOSTAT_IO_MISS_NUM(ciostat)    = 0;

    CIOSTAT_IO_HIT_RATIO(ciostat)   = 0.0;

    return (EC_TRUE);
}

EC_BOOL ciostat_inc_io_hit(CIOSTAT *ciostat)
{
    CIOSTAT_IO_HIT_NUM(ciostat) ++;
    return (EC_TRUE);
}

EC_BOOL ciostat_inc_io_miss(CIOSTAT *ciostat)
{
    CIOSTAT_IO_MISS_NUM(ciostat) ++;
    return (EC_TRUE);
}

REAL ciostat_get_io_hit_ratio(const CIOSTAT *ciostat)
{
    return CIOSTAT_IO_HIT_RATIO(ciostat);
}

EC_BOOL ciostat_calc_io_ratio(CIOSTAT *ciostat, const uint64_t cur_time_ms, const uint64_t interval_ms)
{
    if(cur_time_ms >= CIOSTAT_NTIME_MS(ciostat) + interval_ms)
    {
        uint64_t    elapsed_ms;
        uint32_t    io_num;

        elapsed_ms = (cur_time_ms - CIOSTAT_NTIME_MS(ciostat));
        io_num     = CIOSTAT_IO_HIT_NUM(ciostat) + CIOSTAT_IO_MISS_NUM(ciostat);

        if(0 < io_num)
        {
            CIOSTAT_IO_HIT_RATIO(ciostat) =
                    (CIOSTAT_IO_HIT_NUM(ciostat) * 1000 * 1.0) / (io_num * elapsed_ms * 1.0);
        }
        else
        {
            CIOSTAT_IO_HIT_RATIO(ciostat) = 0.0;
        }

        CIOSTAT_IO_HIT_NUM(ciostat)  = 0; /*clean up*/
        CIOSTAT_IO_MISS_NUM(ciostat) = 0; /*clean up*/

        CIOSTAT_NTIME_MS(ciostat)    = cur_time_ms + interval_ms;
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
