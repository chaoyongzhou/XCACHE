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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cbytes.h"
#include "cmc.h"

#include "cmmap.h"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMC_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMC_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

/**
*
* start CMC module
*
**/
CMC_MD *cmc_start(const UINT32 mem_disk_size /*in byte*/, const UINT32 sata_disk_size/*in byte*/)
{
    CMC_MD  *cmc_md;
    UINT32   key_max_num;

    UINT32   vdisk_num;
    uint8_t  np_model;

    init_static_mem();

    cmcpgd_model_search(mem_disk_size, &vdisk_num);
    if(EC_FALSE == c_check_is_uint16_t(vdisk_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_start: vdisk_num %ld is invalid\n", vdisk_num);
        return (NULL_PTR);
    }

    if(EC_FALSE == cmcnp_model_search(mem_disk_size, &np_model))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_start: no np_model for mem disk size %ld\n",
                                             mem_disk_size);
        return (NULL_PTR);
    }

    /*one key for one page in sata disk*/
    key_max_num = (sata_disk_size >> CMCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_start: sata disk size %ld, page size %u => key max num %ld\n",
                    sata_disk_size, CMCPGB_PAGE_SIZE_NBYTES, key_max_num);

    /* create a new module node */
    cmc_md = safe_malloc(sizeof(CMC_MD), LOC_CMC_0001);
    if(NULL_PTR == cmc_md)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_start: start CMC failed\n");
        return (NULL_PTR);
    }

    /* initialize new one CMC module */
    CMC_MD_DN(cmc_md)         = NULL_PTR;
    CMC_MD_NP(cmc_md)         = NULL_PTR;
    CMC_MD_CMMAP_NODE(cmc_md) = NULL_PTR;

    cmcnp_degrade_cb_init(CMC_MD_NP_DEGRADE_CB(cmc_md));

    CMC_MD_FC_MAX_SPEED_FLAG(cmc_md) = BIT_FALSE;
    CMC_MD_SHM_NP_FLAG(cmc_md)       = BIT_FALSE;
    CMC_MD_SHM_DN_FLAG(cmc_md)       = BIT_FALSE;
    CMC_MD_RDONLY_FLAG(cmc_md)       = BIT_FALSE;
    CMC_MD_NP_MODEL(cmc_md)          = np_model;
    CMC_MD_VDISK_NUM(cmc_md)         = (uint16_t)vdisk_num;
    CMC_MD_KEY_MAX_NUM(cmc_md)       = key_max_num;

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_start: start cmc done\n");

    return (cmc_md);
}

/**
*
* end CMC module
*
**/
void cmc_end(CMC_MD *cmc_md)
{
    if(NULL_PTR == cmc_md)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_end: cmc %p not exist.\n", cmc_md);
        return;
    }

    cmc_close_np(cmc_md);
    cmc_close_dn(cmc_md);

    cmcnp_degrade_cb_clean(CMC_MD_NP_DEGRADE_CB(cmc_md));

    CMC_MD_FC_MAX_SPEED_FLAG(cmc_md) = BIT_FALSE;
    CMC_MD_SHM_NP_FLAG(cmc_md)       = BIT_FALSE;
    CMC_MD_SHM_DN_FLAG(cmc_md)       = BIT_FALSE;
    CMC_MD_RDONLY_FLAG(cmc_md)       = BIT_FALSE;

    CMC_MD_NP_MODEL(cmc_md)          = CMCNP_ERR_MODEL;
    CMC_MD_VDISK_NUM(cmc_md)         = 0;
    CMC_MD_KEY_MAX_NUM(cmc_md)       = 0;

    CMC_MD_CMMAP_NODE(cmc_md)        = NULL_PTR;

    safe_free(cmc_md, LOC_CMC_0002);

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_end: stop cmc done\n");

    return ;
}

/**
*
* print CMC module
*
**/
void cmc_print(LOG *log, const CMC_MD *cmc_md)
{
    cmc_show_np(cmc_md, log);
    cmc_show_dn(cmc_md, log);

    return;
}

/**
*
* cleanup cmc name node and data node
*
**/
EC_BOOL cmc_clean(CMC_MD *cmc_md)
{
    cmc_close_np(cmc_md);
    cmc_close_dn(cmc_md);

    return (EC_TRUE);
}

/**
*
* create cmc name node and data node
*
**/
EC_BOOL cmc_create(CMC_MD *cmc_md)
{
    if(EC_FALSE == cmc_create_np(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create: create np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create: create np done\n");

    if(EC_FALSE == cmc_create_dn(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create: create dn failed\n");

        cmc_close_np(cmc_md);
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create: create dn done\n");

    return (EC_TRUE);
}

/**
*
* create cmc name node and data node in shm
*
**/
EC_BOOL cmc_create_shm(CMC_MD *cmc_md)
{
    if(EC_FALSE == cmc_create_np_shm(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_shm: create np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create_shm: create np done\n");

    if(EC_FALSE == cmc_create_dn_shm(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_shm: create dn failed\n");

        cmc_close_np(cmc_md);
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create_shm: create dn done\n");

    return (EC_TRUE);
}

/**
*
* open cmc name node and data node in shm
*
**/
EC_BOOL cmc_open_shm(CMC_MD *cmc_md)
{
    if(EC_FALSE == cmc_open_np_shm(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_open_shm: open np in shm failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_open_shm: open np in shm done\n");

    if(EC_FALSE == cmc_open_dn_shm(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_open_shm: open dn in shm failed\n");

        cmc_close_np(cmc_md);
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_open_shm: open dn in shm done\n");

    return (EC_TRUE);
}

/*mount mmap node*/
EC_BOOL cmc_mount_mmap(CMC_MD *cmc_md, CMMAP_NODE *cmmap_node)
{
    if(NULL_PTR == CMC_MD_CMMAP_NODE(cmc_md))
    {
        CMC_MD_CMMAP_NODE(cmc_md) = cmmap_node;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*umount mmap node*/
EC_BOOL cmc_umount_mmap(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_CMMAP_NODE(cmc_md))
    {
        cmc_close_np(cmc_md);
        cmc_close_dn(cmc_md);

        CMC_MD_CMMAP_NODE(cmc_md) = NULL_PTR;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*get mmap node*/
CMMAP_NODE *cmc_get_mmap(CMC_MD *cmc_md)
{
    return CMC_MD_CMMAP_NODE(cmc_md);
}

/**
*
* try to quit cmc
*
**/
EC_BOOL cmc_try_quit(CMC_MD *cmc_md)
{
    static UINT32  warning_counter = 0; /*suppress warning report*/

    cmc_flow_control_enable_max_speed(cmc_md);

    cmc_retire(cmc_md, (UINT32)~0, NULL_PTR); /*try to retire all*/

    cmc_recycle(cmc_md, (UINT32)~0, NULL_PTR);/*try to recycle all*/

    cmc_process_degrades(cmc_md, CMC_DEGRADE_TRAFFIC_32MB,
                         (UINT32)~0, /*try to degrade all*/
                         (UINT32)CMC_PROCESS_DEGRADE_MAX_NUM, NULL_PTR);

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        if(EC_FALSE == cmcnp_lru_list_is_empty(CMC_MD_NP(cmc_md)))
        {
            if(0 == (warning_counter % 1000))
            {
                dbg_log(SEC_0118_CMC, 6)(LOGSTDOUT, "[DEBUG] cmc_try_quit: "
                                                    "lru list is not empty\n");
            }

            warning_counter ++;
            return (EC_FALSE);
        }

        if(EC_FALSE == cmcnp_del_list_is_empty(CMC_MD_NP(cmc_md)))
        {
            if(0 == (warning_counter % 1000))
            {
                dbg_log(SEC_0118_CMC, 6)(LOGSTDOUT, "[DEBUG] cmc_try_quit: "
                                                    "del list is not empty\n");
            }

            warning_counter ++;

            return (EC_FALSE);
        }
    }

    warning_counter = 0;

    return (EC_TRUE);
}

EC_BOOL cmc_try_restart(CMC_MD *cmc_md)
{
    cmc_flow_control_enable_max_speed(cmc_md);

    cmc_retire(cmc_md, CMC_TRY_RETIRE_MAX_NUM, NULL_PTR); /*try to retire all*/

    cmc_recycle(cmc_md, CMC_TRY_RECYCLE_MAX_NUM, NULL_PTR);/*try to recycle all*/

    cmc_process_degrades(cmc_md, CMC_DEGRADE_TRAFFIC_32MB,
                         (UINT32)CMC_SCAN_DEGRADE_MAX_NUM,
                         (UINT32)CMC_PROCESS_DEGRADE_MAX_NUM,
                         NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cmc_set_read_only(CMC_MD *cmc_md)
{
    if(BIT_TRUE == CMC_MD_RDONLY_FLAG(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_set_read_only: "
                                            "cmc is set already read-only\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        cmcnp_set_read_only(CMC_MD_NP(cmc_md));
    }

    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        cmcdn_set_read_only(CMC_MD_DN(cmc_md));
    }

    CMC_MD_RDONLY_FLAG(cmc_md) = BIT_TRUE;

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_set_read_only: "
                                        "set cmc read-only\n");

    return (EC_TRUE);
}

EC_BOOL cmc_unset_read_only(CMC_MD *cmc_md)
{
    if(BIT_FALSE == CMC_MD_RDONLY_FLAG(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_unset_read_only: "
                                            "cmc was not set read-only\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        cmcnp_unset_read_only(CMC_MD_NP(cmc_md));
    }

    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        cmcdn_unset_read_only(CMC_MD_DN(cmc_md));
    }

    CMC_MD_RDONLY_FLAG(cmc_md) = BIT_FALSE;

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_unset_read_only: "
                                        "unset cmc read-only\n");

    return (EC_TRUE);
}

EC_BOOL cmc_is_read_only(const CMC_MD *cmc_md)
{
    if(BIT_FALSE == CMC_MD_RDONLY_FLAG(cmc_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
* flow control enable max speed
*
**/
EC_BOOL cmc_flow_control_enable_max_speed(CMC_MD *cmc_md)
{
    if(NULL_PTR != cmc_md)
    {
        CMC_MD_FC_MAX_SPEED_FLAG(cmc_md) = BIT_TRUE;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
*
* flow control disable max speed
*
**/
EC_BOOL cmc_flow_control_disable_max_speed(CMC_MD *cmc_md)
{
    if(NULL_PTR != cmc_md)
    {
        CMC_MD_FC_MAX_SPEED_FLAG(cmc_md) = BIT_FALSE;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
 *
 *  note: traffic flow determined by both cmc used capacity and traffic speed
 *
 *  when cmc has enough capacity (< low ratio), do not control traffic flow as possible as we can.
 *  when cmc used capacity reaches high ratio, control traffic flow as traffic speed marked.
 *
 *  cmc traffic flow has 3 categories: 10Mbps, 20Mbps, 30Mbps, or 40Mbps.
 *
 **/
STATIC_CAST static void __cmc_flow_control(const uint64_t mem_traffic_bps, const REAL deg_ratio,
                                                uint64_t *degrade_traffic_bps)
{
    if(CMC_DEGRADE_LO_RATIO > deg_ratio)
    {
        if(mem_traffic_bps >= CMC_TRAFFIC_36MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_24MB;
        }
        else if(mem_traffic_bps >= CMC_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_16MB;
        }
        else
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_08MB;
        }
    }
    else if(CMC_DEGRADE_MD_RATIO > deg_ratio)
    {
        if(mem_traffic_bps >= CMC_TRAFFIC_36MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_32MB;
        }
        else if(mem_traffic_bps >= CMC_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_24MB;
        }
        else
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_16MB;
        }
    }
    else if(CMC_DEGRADE_HI_RATIO > deg_ratio)
    {
        if(mem_traffic_bps >= CMC_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_36MB;
        }
        else if(mem_traffic_bps >= CMC_TRAFFIC_16MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_32MB;
        }
        else
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_24MB;
        }
    }
    else
    {
        if(mem_traffic_bps >= CMC_TRAFFIC_36MB)
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_40MB;
        }
        else
        {
            (*degrade_traffic_bps) = CMC_DEGRADE_TRAFFIC_36MB;
        }
    }

    return;
}

STATIC_CAST static void __cmc_flow_control_02(const uint64_t mem_traffic_bps, const REAL deg_ratio,
                                                uint64_t *degrade_traffic_bps)
{
    static REAL        deg_ratio_saved       = 0.0;
    static uint64_t    degrade_traffic_saved = 10;   /*MB/s*/
    const REAL                  deg_ratio_delta       = 0.01; /*1%*/

    const uint64_t              degrade_traffic_min   = 10;   /*MB/s*/
    const uint64_t              degrade_traffic_max   = 60;   /*MB/s*/

    static uint64_t             time_msec_next        = 0;    /*init*/
    const uint64_t              time_msec_interval    = 100;  /*ms*/

    uint64_t                    time_msec_cur;

    time_msec_cur = c_get_cur_time_msec();

    if(time_msec_cur >= time_msec_next)
    {
        time_msec_next += time_msec_interval; /*update*/

        if(deg_ratio_delta > deg_ratio)
        {
            degrade_traffic_saved = degrade_traffic_min;
            deg_ratio_saved       = deg_ratio;
        }
        else if(CMC_DEGRADE_LO_RATIO > deg_ratio)
        {
            /*step is 1*/

            if(deg_ratio > deg_ratio_saved + deg_ratio_delta)
            {
                degrade_traffic_saved += 1;
                deg_ratio_saved        = deg_ratio;
            }
            else if(deg_ratio < deg_ratio_saved - deg_ratio_delta)
            {
                degrade_traffic_saved -= 1;
                deg_ratio_saved        = deg_ratio;
            }
        }
        else if(CMC_DEGRADE_MD_RATIO > deg_ratio)
        {
            /*step is 2*/

            if(deg_ratio > deg_ratio_saved + deg_ratio_delta)
            {
                degrade_traffic_saved += 2;
                deg_ratio_saved        = deg_ratio;
            }
            else if(deg_ratio < deg_ratio_saved - deg_ratio_delta)
            {
                degrade_traffic_saved -= 2;
                deg_ratio_saved        = deg_ratio;
            }
        }
        else if(CMC_DEGRADE_HI_RATIO > deg_ratio)
        {
            /*step is 3*/

            if(deg_ratio > deg_ratio_saved + deg_ratio_delta)
            {
                degrade_traffic_saved += 3;
                deg_ratio_saved        = deg_ratio;
            }
            else if(deg_ratio < deg_ratio_saved - deg_ratio_delta)
            {
                degrade_traffic_saved -= 3;
                deg_ratio_saved        = deg_ratio;
            }
        }
        else
        {
            degrade_traffic_saved = degrade_traffic_max;
            deg_ratio_saved       = deg_ratio;
        }

        if(degrade_traffic_min > degrade_traffic_saved)
        {
            degrade_traffic_saved = degrade_traffic_min;
        }

        if(degrade_traffic_max < degrade_traffic_saved)
        {
            degrade_traffic_saved = degrade_traffic_max;
        }
    }

    (*degrade_traffic_bps) = (degrade_traffic_saved << 23);

    return;
}

/*--- WARNING: deprecated ---*/
/**
*
*   WARNING: deprecated flow control 03. SHOULD NEVER BE USED!
*
*            when deg ratio or used ratio reaches max 1.00,
*            degrade speed would keep unchanged which is out of expectation!
*
**/
STATIC_CAST static void __cmc_flow_control_03_obsolete(const uint64_t mem_traffic_bps, const REAL deg_ratio,
                                                uint64_t *degrade_traffic_bps)
{
    static REAL        deg_ratio_saved       = 0.0;
    static uint64_t    degrade_traffic_saved = 10;   /*MB/s*/
    const REAL                  deg_ratio_delta       = 0.01; /*1%*/

    const uint64_t              degrade_traffic_min   = 10;   /*MB/s*/
    const uint64_t              degrade_traffic_max   = 60;   /*MB/s*/

    static uint64_t             time_msec_next        = 0;    /*init*/
    const uint64_t              time_msec_interval    = 100;  /*ms*/

    uint64_t                    time_msec_cur;

    time_msec_cur = c_get_cur_time_msec();

    if(time_msec_cur >= time_msec_next)
    {
        time_msec_next += time_msec_interval; /*update*/

        if(deg_ratio_delta > deg_ratio)
        {
            degrade_traffic_saved = degrade_traffic_min;
            deg_ratio_saved       = deg_ratio;
        }
        else if(deg_ratio > deg_ratio_saved + deg_ratio_delta)
        {
            degrade_traffic_saved += 2;
            deg_ratio_saved        = deg_ratio;
        }
        else if(deg_ratio < deg_ratio_saved - deg_ratio_delta)
        {
            degrade_traffic_saved -= 2;
            deg_ratio_saved        = deg_ratio;
        }

        if(degrade_traffic_min > degrade_traffic_saved)
        {
            degrade_traffic_saved = degrade_traffic_min;
        }

        if(degrade_traffic_max < degrade_traffic_saved)
        {
            degrade_traffic_saved = degrade_traffic_max;
        }
    }

    (*degrade_traffic_bps) = (degrade_traffic_saved << 23);

    return;
}

/**
*
* recycle deleted or retired space
*
**/
void cmc_process(CMC_MD *cmc_md, const uint64_t mem_traffic_bps, REAL  mem_hit_ratio,
                     const uint64_t amd_read_traffic_bps, const uint64_t amd_write_traffic_bps)
{
    uint64_t    degrade_traffic_bps;

    UINT32      degrade_complete_num;
    UINT32      retire_complete_num;
    UINT32      recycle_complete_num;

    REAL        used_ratio;

    REAL        deg_ratio;
    uint32_t    deg_num;

    used_ratio = cmc_used_ratio(cmc_md);

    deg_ratio  = cmc_deg_ratio(cmc_md);
    deg_num    = cmc_deg_num(cmc_md);

    degrade_complete_num = 0;
    retire_complete_num  = 0;
    recycle_complete_num = 0;

    __cmc_flow_control(mem_traffic_bps,
                       deg_ratio,
                      &degrade_traffic_bps);

    if(BIT_TRUE == CMC_MD_FC_MAX_SPEED_FLAG(cmc_md))
    {
        /*override*/
        degrade_traffic_bps = CMC_DEGRADE_TRAFFIC_32MB;
    }

    cmc_process_degrades(cmc_md, degrade_traffic_bps,
                         (UINT32)CMC_SCAN_DEGRADE_MAX_NUM,
                         (UINT32)CMC_PROCESS_DEGRADE_MAX_NUM,
                         &degrade_complete_num);

    if(CMC_DEGRADE_HI_RATIO <= used_ratio)
    {
        cmc_retire(cmc_md, CMC_TRY_RETIRE_MAX_NUM, &retire_complete_num);
    }
#if 0
    if(CMC_DEGRADE_HI_RATIO > deg_ratio)
    {
        /*speed up retire*/
        if(CMC_READ_TRAFFIC_08MB >= amd_read_traffic_bps
        && CMC_WRITE_TRAFFIC_08MB >= amd_write_traffic_bps)
        {
            cmc_retire(cmc_md, CMC_TRY_RETIRE_MAX_NUM << 2, &retire_complete_num);
        }
        else if(CMC_READ_TRAFFIC_12MB >= amd_read_traffic_bps
             && CMC_WRITE_TRAFFIC_12MB >= amd_write_traffic_bps)
        {
            cmc_retire(cmc_md, CMC_TRY_RETIRE_MAX_NUM << 1, &retire_complete_num);
        }
    }
#endif
    cmc_recycle(cmc_md, CMC_TRY_RECYCLE_MAX_NUM, &recycle_complete_num);

    if(0 < degrade_complete_num
    || 0 < retire_complete_num
    || 0 < recycle_complete_num)
    {
        dbg_log(SEC_0118_CMC, 2)(LOGSTDOUT, "[DEBUG] cmc_process: "
                                            "used %.2f, r/w %ld/%ld MBps, hit %.2f, "
                                            "deg: %u, %.2f, %ld MBps, "
                                            "=> degrade %ld, retire %ld, recycle %ld\n",
                                            used_ratio,
                                            amd_read_traffic_bps >> 23,
                                            amd_write_traffic_bps >> 23,
                                            mem_hit_ratio,
                                            deg_num,
                                            deg_ratio,
                                            degrade_traffic_bps >> 23,
                                            degrade_complete_num,
                                            retire_complete_num,
                                            recycle_complete_num);
    }

    return;
}

void cmc_process_no_degrade(CMC_MD *cmc_md)
{
    UINT32      retire_complete_num;
    UINT32      recycle_complete_num;

    REAL        used_ratio;

    REAL        deg_ratio;
    uint32_t    deg_num;

    used_ratio = cmc_used_ratio(cmc_md);

    deg_ratio  = cmc_deg_ratio(cmc_md);
    deg_num    = cmc_deg_num(cmc_md);

    retire_complete_num  = 0;
    recycle_complete_num = 0;

    cmc_retire(cmc_md, CMC_TRY_RETIRE_MAX_NUM, &retire_complete_num);
    cmc_recycle(cmc_md, CMC_TRY_RECYCLE_MAX_NUM, &recycle_complete_num);

    if(0 < retire_complete_num
    || 0 < recycle_complete_num)
    {
        dbg_log(SEC_0118_CMC, 2)(LOGSTDOUT, "[DEBUG] cmc_process_no_degrade: "
                                            "used %.2f, "
                                            "deg: %u, %.2f "
                                            "=> retire %ld, recycle %ld\n",
                                            used_ratio,
                                            deg_num,
                                            deg_ratio,
                                            retire_complete_num,
                                            recycle_complete_num);
    }

    return;
}

/**
*
*  degrade pages of cmc module
*
**/
void cmc_process_degrades(CMC_MD *cmc_md, const uint64_t degrade_traffic_bps,
                                 const UINT32 scan_max_num,
                                 const UINT32 expect_degrade_num,
                                 UINT32 *complete_degrade_num)
{
    static uint64_t     time_msec_next = 0; /*init*/

    UINT32      complete_degrade_num_t;

    complete_degrade_num_t = 0;

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        uint64_t    time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        while(time_msec_cur >= time_msec_next)
        {
            uint64_t    time_msec_cost; /*msec cost for degrading from ssd to sata*/

            /*degrade 4MB at most once time*/
            cmcnp_degrade(CMC_MD_NP(cmc_md), scan_max_num, expect_degrade_num, &complete_degrade_num_t);
            if(0 == complete_degrade_num_t)
            {
                break; /*fall through*/
            }

            if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_08MB) /*8MB/s*/
            {
                /*
                *
                * if flow control is 8MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (8MB/s)
                *                = ((n * 2^m * 125) / (2^20)) ms
                *                = (((n * 125) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 500
                * if n = 8 , time cost msec = 250
                * if n = 4 , time cost msec = 125
                * if n = 2 , time cost msec = 62
                * if n = 1 , time cost msec = 31
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 125) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_16MB) /*16MB/s*/
            {
                /*
                *
                * if flow control is 16MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (16MB/s)
                *                = ((n * 2^m * 62) / (2^20)) ms
                *                = (((n * 62) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 248
                * if n = 8 , time cost msec = 124
                * if n = 4 , time cost msec = 62
                * if n = 2 , time cost msec = 31
                * if n = 1 , time cost msec = 15
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 62) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_20MB) /*20MB/s*/
            {
                /*
                *
                * if flow control is 20MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (20MB/s)
                *                = ((n * 2^m * 50) / (2^20)) ms
                *                = (((n * 50) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 200
                * if n = 8 , time cost msec = 100
                * if n = 4 , time cost msec = 50
                * if n = 2 , time cost msec = 25
                * if n = 1 , time cost msec = 12
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 50) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_24MB) /*24MB/s*/
            {
                /*
                *
                * if flow control is 24MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (24MB/s)
                *                = ((n * 2^m * 41) / (2^20)) ms
                *                = (((n * 41) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 164
                * if n = 8 , time cost msec = 82
                * if n = 4 , time cost msec = 41
                * if n = 2 , time cost msec = 20
                * if n = 1 , time cost msec = 10
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 41) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_28MB) /*28MB/s*/
            {
                /*
                *
                * if flow control is 28MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (28MB/s)
                *                = ((n * 2^m * 36) / (2^20)) ms
                *                = (((n * 36) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 144
                * if n = 8 , time cost msec = 72
                * if n = 4 , time cost msec = 36
                * if n = 2 , time cost msec = 18
                * if n = 1 , time cost msec = 9
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 36) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_32MB)/*32MB/s*/
            {
                /*
                *
                * if flow control is 32MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (32MB/s)
                *        (about) = ((n * 2^m * 31) / (2^20)) ms
                *                = (((n * 31) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 124
                * if n = 8 , time cost msec = 62
                * if n = 4 , time cost msec = 31
                * if n = 2 , time cost msec = 15
                * if n = 1 , time cost msec = 7
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 31) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }
            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_36MB)/*36MB/s*/
            {
                /*
                *
                * if flow control is 36MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (36MB/s)
                *                = ((n * 2^m * 28) / (2^20)) ms
                *                = (((n * 28) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 112
                * if n = 8 , time cost msec = 56
                * if n = 4 , time cost msec = 28
                * if n = 2 , time cost msec = 14
                * if n = 1 , time cost msec = 7
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 28) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CMC_DEGRADE_TRAFFIC_40MB)/*40MB/s*/
            {
                /*
                *
                * if flow control is 40MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (40MB/s)
                *                = ((n * 2^m * 25) / (2^20)) ms
                *                = (((n * 25) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 100
                * if n = 8 , time cost msec = 50
                * if n = 4 , time cost msec = 25
                * if n = 2 , time cost msec = 12
                * if n = 1 , time cost msec = 6
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 25) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }
            else/*60MB/s*/
            {
                /*
                *
                * if flow control is 60MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (60MB/s)
                *        (about) = ((n * 2^m * 16) / (2^20)) ms
                *                = (((n * 16) << m) >> 20) ms
                * where 2^m is cmc page size in bytes.
                * e.g.,
                * when cmc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 64
                * if n = 8 , time cost msec = 32
                * if n = 4 , time cost msec = 16
                * if n = 2 , time cost msec = 8
                * if n = 1 , time cost msec = 4
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 16) << CMCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "[DEBUG] cmc_process_degrades: "
                                                "complete %ld, expected cost %ld msec\n",
                                                complete_degrade_num_t, time_msec_cost);

            time_msec_next = time_msec_cur + time_msec_cost;

            break; /*fall through*/
        }
    }

    if(NULL_PTR != complete_degrade_num)
    {
        (*complete_degrade_num) = complete_degrade_num_t;
    }

    return;
}

/**
*
*   note: cmc degrading method 02 is for high performance ssd.
*         when launching, degrading speed would reach max in short time
*         and then adjust automatically until deg ratio unchanged.
*
**/
void cmc_process_degrades_02(CMC_MD *cmc_md, const uint64_t degrade_traffic_bps,
                                 const UINT32 scan_max_num,
                                 const UINT32 expect_degrade_num,
                                 UINT32 *complete_degrade_num)
{
    static uint64_t  time_msec_next = 0; /*init*/

    UINT32      complete_degrade_num_t;

    complete_degrade_num_t = 0;

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        uint64_t    time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        while(time_msec_cur >= time_msec_next)
        {
            uint64_t    complete_degrade_nbits;
            uint64_t    time_msec_cost; /*msec cost for degrading from ssd to sata*/

            /*degrade 4MB at most once time*/
            cmcnp_degrade(CMC_MD_NP(cmc_md), scan_max_num, expect_degrade_num, &complete_degrade_num_t);
            if(0 == complete_degrade_num_t)
            {
                break; /*fall through*/
            }

            complete_degrade_nbits = ((((uint64_t)complete_degrade_num_t) << CMCPGB_PAGE_SIZE_NBITS) << 3);
            time_msec_cost =  (complete_degrade_nbits * 1000)/ degrade_traffic_bps; /*in ms*/

            dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "[DEBUG] cmc_process_degrades: "
                                                "complete %ld, degrade_traffic_bps %ld, expected cost %ld msec\n",
                                                complete_degrade_num_t, degrade_traffic_bps, time_msec_cost);

            time_msec_next = time_msec_cur + time_msec_cost;

            break; /*fall through*/
        }
    }

    if(NULL_PTR != complete_degrade_num)
    {
        (*complete_degrade_num) = complete_degrade_num_t;
    }

    return;
}

/**
*
*  degrade all pages of cmc module
*
**/
void cmc_process_all_degrades(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        UINT32      complete_degrade_num;

        cmcnp_degrade_all(CMC_MD_NP(cmc_md), &complete_degrade_num);

        dbg_log(SEC_0118_CMC, 6)(LOGSTDOUT, "[DEBUG] cmc_process_all_degrades: complete %ld\n",
                                            complete_degrade_num);
    }

    return;
}

/**
*
*  create name node
*
**/
EC_BOOL cmc_create_np(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: np already exist\n");
        return (EC_FALSE);
    }

    CMC_MD_NP(cmc_md) = cmcnp_create((uint32_t)0/*cmcnp_id*/,
                                     CMC_MD_NP_MODEL(cmc_md),
                                     CMC_MD_KEY_MAX_NUM(cmc_md));
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: create np failed\n");
        return (EC_FALSE);
    }

    CMC_MD_SHM_NP_FLAG(cmc_md) = BIT_FALSE;

    /*np inherit degrade callback from cmc module*/
    cmcnp_degrade_cb_clone(CMC_MD_NP_DEGRADE_CB(cmc_md), CMCNP_DEGRADE_CB(CMC_MD_NP(cmc_md)));

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create_np: create np done\n");

    return (EC_TRUE);
}

/**
*
*  create name node in shared memory
*
**/
EC_BOOL cmc_create_np_shm(CMC_MD *cmc_md)
{
    uint32_t        np_id;

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np_shm: np already exist\n");
        return (EC_FALSE);
    }

    np_id = 0;

    CMC_MD_NP(cmc_md) = cmcnp_create_shm(CMC_MD_CMMAP_NODE(cmc_md),
                                        np_id,
                                        CMC_MD_NP_MODEL(cmc_md),
                                        CMC_MD_KEY_MAX_NUM(cmc_md));
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np_shm: create np failed\n");
        return (EC_FALSE);
    }

    CMC_MD_SHM_NP_FLAG(cmc_md) = BIT_TRUE;

    /*np inherit degrade callback from cmc module*/
    cmcnp_degrade_cb_clone(CMC_MD_NP_DEGRADE_CB(cmc_md), CMCNP_DEGRADE_CB(CMC_MD_NP(cmc_md)));

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create_np_shm: create np done\n");

    return (EC_TRUE);
}

/**
*
*  open name node in shared memory
*
**/
EC_BOOL cmc_open_np_shm(CMC_MD *cmc_md)
{
    uint32_t        np_id;

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_open_np_shm: np already exist\n");
        return (EC_FALSE);
    }

    np_id = 0;

    CMC_MD_NP(cmc_md) = cmcnp_open_shm(CMC_MD_CMMAP_NODE(cmc_md),
                                       np_id,
                                       CMC_MD_NP_MODEL(cmc_md),
                                       CMC_MD_KEY_MAX_NUM(cmc_md));
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_open_np_shm: open np failed\n");
        return (EC_FALSE);
    }

    CMC_MD_SHM_NP_FLAG(cmc_md) = BIT_TRUE;

    /*np inherit degrade callback from cmc module*/
    cmcnp_degrade_cb_clone(CMC_MD_NP_DEGRADE_CB(cmc_md), CMCNP_DEGRADE_CB(CMC_MD_NP(cmc_md)));

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_open_np_shm: open np done\n");

    return (EC_TRUE);
}

/**
*
*  close name node
*
**/
EC_BOOL cmc_close_np(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        if(BIT_TRUE == CMC_MD_SHM_NP_FLAG(cmc_md))
        {
            cmcnp_close(CMC_MD_NP(cmc_md));
        }
        else
        {
            cmcnp_free(CMC_MD_NP(cmc_md));
        }

        CMC_MD_NP(cmc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}


/**
*
*  create data node
*
**/
EC_BOOL cmc_create_dn(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    CMC_MD_DN(cmc_md) = cmcdn_create(CMC_MD_VDISK_NUM(cmc_md));
    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    CMC_MD_SHM_DN_FLAG(cmc_md) = BIT_FALSE;

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create_dn: create dn done\n");

    return (EC_TRUE);
}

/**
*
*  create data node in shared memory
*
**/
EC_BOOL cmc_create_dn_shm(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn_shm: dn already exist\n");
        return (EC_FALSE);
    }

    CMC_MD_DN(cmc_md) = cmcdn_create_shm(CMC_MD_CMMAP_NODE(cmc_md), CMC_MD_VDISK_NUM(cmc_md));
    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn_shm: create dn failed\n");
        return (EC_FALSE);
    }

    CMC_MD_SHM_DN_FLAG(cmc_md) = BIT_TRUE;

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_create_dn_shm: create dn done\n");

    return (EC_TRUE);
}

/**
*
*  open data node in shared memory
*
**/
EC_BOOL cmc_open_dn_shm(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_open_dn_shm: dn already exist\n");
        return (EC_FALSE);
    }

    CMC_MD_DN(cmc_md) = cmcdn_open_shm(CMC_MD_CMMAP_NODE(cmc_md), CMC_MD_VDISK_NUM(cmc_md));
    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_open_dn_shm: open dn failed\n");
        return (EC_FALSE);
    }

    CMC_MD_SHM_DN_FLAG(cmc_md) = BIT_TRUE;
    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_open_dn_shm: open dn done\n");

    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL cmc_close_dn(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        if(BIT_TRUE == CMC_MD_SHM_DN_FLAG(cmc_md))
        {
            cmcdn_close(CMC_MD_DN(cmc_md));
        }
        else
        {
            cmcdn_free(CMC_MD_DN(cmc_md));
        }

        CMC_MD_DN(cmc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}

/**
*
*  find item
*
**/
CMCNP_ITEM *cmc_find(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key)
{
    uint32_t          node_pos;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_find: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 7)(LOGSTDOUT, "warn:cmc_find: miss key [%u, %u)\n",
                        CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));
        return (NULL_PTR);
    }

    node_pos = cmcnp_search(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_find: search failed\n");
        return (NULL_PTR);
    }

    return cmcnp_fetch(CMC_MD_NP(cmc_md), node_pos);
}

/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cmc_reserve_hash_dn(CMC_MD *cmc_md, const UINT32 data_len, const uint32_t path_hash, CMCNP_FNODE *cmcnp_fnode)
{
    CMCNP_INODE *cmcnp_inode;
    CMCPGV      *cmcpgv;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: cmc is read-only\n");
        return (EC_FALSE);
    }

    if(CMCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CMCDN_CMCPGV(CMC_MD_DN(cmc_md)))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cmcpgv = CMCDN_CMCPGV(CMC_MD_DN(cmc_md));
    if(NULL_PTR == CMCPGV_HEADER(cmcpgv))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CMCPGV_PAGE_DISK_NUM(cmcpgv))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    fail_tries = 0;
    for(;;)
    {
        size    = (uint32_t)(data_len);
        disk_no = (uint16_t)(path_hash % CMCPGV_PAGE_DISK_NUM(cmcpgv));

        if(EC_TRUE == cmcpgv_new_space_from_disk(cmcpgv, size, disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        /*try again*/
        if(EC_TRUE == cmcpgv_new_space(cmcpgv, size, &disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        fail_tries ++;

        if(1 < fail_tries) /*try once only*/
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: "
                                                "new %ld bytes space from vol failed\n",
                                                data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0118_CMC, 7)(LOGSTDOUT, "warn:__cmc_reserve_hash_dn: "
                                            "no %ld bytes space, try to retire & recycle\n",
                                            data_len);
        cmc_retire(cmc_md, (UINT32)CMC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cmc_recycle(cmc_md, (UINT32)CMC_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    CMC_ASSERT(CMCPGB_PAGE_SIZE_NBYTES == size);

    cmcnp_fnode_init(cmcnp_fnode);
    CMCNP_FNODE_PAGENUM(cmcnp_fnode) = (uint16_t)(size >> CMCPGB_PAGE_SIZE_NBITS);
    CMCNP_FNODE_REPNUM(cmcnp_fnode)  = 1;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    CMCNP_INODE_DISK_NO(cmcnp_inode)    = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL cmc_reserve_dn(CMC_MD *cmc_md, const UINT32 data_len, CMCNP_FNODE *cmcnp_fnode)
{
    CMCNP_INODE *cmcnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_reserve_dn: cmc is read-only\n");
        return (EC_FALSE);
    }

    if(CMCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cmcpgv_new_space(CMCDN_CMCPGV(CMC_MD_DN(cmc_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: new %ld bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }

     CMC_ASSERT(CMCPGB_PAGE_SIZE_NBYTES == size);

    cmcnp_fnode_init(cmcnp_fnode);
    CMCNP_FNODE_PAGENUM(cmcnp_fnode) = (uint16_t)(size >> CMCPGB_PAGE_SIZE_NBITS);
    CMCNP_FNODE_REPNUM(cmcnp_fnode) = 1;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    CMCNP_INODE_DISK_NO(cmcnp_inode)    = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL cmc_release_dn(CMC_MD *cmc_md, const CMCNP_FNODE *cmcnp_fnode)
{
    const CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_release_dn: cmc is read-only\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(CMCPGB_SIZE_NBYTES < file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer cmc_page_write: when file size is zero, only reserve np but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_release_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    if(EC_FALSE == cmcpgv_free_space(CMCDN_CMCPGV(CMC_MD_DN(cmc_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_release_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  reserve a fnode from name node
*
**/
STATIC_CAST static CMCNP_FNODE * __cmc_reserve_np(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_FNODE *cmcnp_fnode;

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:__cmc_reserve_np: cmc is read-only\n");
        return (NULL_PTR);
    }

    cmcnp_fnode = cmcnp_reserve(CMC_MD_NP(cmc_md), cmcnp_key);
    if(NULL_PTR == cmcnp_fnode)
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "warn:__cmc_reserve_np: no name node accept key, try to retire & recycle\n");
        cmc_retire(cmc_md, (UINT32)CMC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cmc_recycle(cmc_md, (UINT32)CMC_TRY_RECYCLE_MAX_NUM, NULL_PTR);

        /*try again*/
        cmcnp_fnode = cmcnp_reserve(CMC_MD_NP(cmc_md), cmcnp_key);
        if(NULL_PTR == cmcnp_fnode)/*Oops!*/
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: no name node accept key\n");
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: np: max %u, used %u, deg %u, dn: max %ld, used %ld\n",
                                                CMCNP_ITEMS_MAX_NUM(CMC_MD_NP(cmc_md)),
                                                CMCNP_ITEMS_USED_NUM(CMC_MD_NP(cmc_md)),
                                                CMCNP_DEG_NODE_NUM(CMC_MD_NP(cmc_md)),
                                                CMCPGV_PAGE_MAX_NUM(CMCDN_CMCPGV(CMC_MD_DN(cmc_md))),
                                                CMCPGV_PAGE_USED_NUM(CMCDN_CMCPGV(CMC_MD_DN(cmc_md))));
            return (NULL_PTR);
        }
    }

    return (cmcnp_fnode);
}


/**
*
*  release a fnode from name node
*
**/
STATIC_CAST static EC_BOOL __cmc_release_np(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_release_np: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:__cmc_release_np: cmc is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_release(CMC_MD_NP(cmc_md), cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_release_np: release key from np failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  locate a file and return base address of the first page
*
**/
UINT8 *cmc_file_locate(CMC_MD *cmc_md, UINT32 *offset, const UINT32 rsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *buff;

    s_offset = (*offset);
    e_offset = (*offset) + rsize;

    buff     = NULL_PTR; /*init*/

    s_page   = (s_offset >> CMCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_locate: "
                                        "offset %ld, rsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), rsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CMCNP_KEY     cmcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        UINT8        *m_buff;

        /*one page only*/
        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(s_page + 0);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(s_page + 1);

        if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_locate: miss page %ld\n",
                            s_page);
            break;
        }

        offset_t = (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CMCPGB_PAGE_SIZE_NBYTES - offset_t);

        m_buff = cmc_page_locate(cmc_md, &cmcnp_key);
        if(NULL_PTR == m_buff)
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_locate: locate page %ld failed\n",
                            s_page);
            break;
        }

        if(NULL_PTR == buff)
        {
            buff = m_buff;
        }

        s_offset += max_len;
    }

    (*offset) = s_offset;

    return (buff);
}

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cmc_file_read(CMC_MD *cmc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    s_offset = (*offset);
    e_offset = (*offset) + rsize;
    m_buff   = buff;

    s_page   = (s_offset >> CMCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_read: "
                                        "offset %ld, rsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), rsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CMCNP_KEY     cmcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES        cbytes;

        /*one page only*/
        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(s_page + 0);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(s_page + 1);

        if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
        {
            dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_read: mem miss page %ld\n",
                            s_page);
            break;
        }

        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_read: mem hit page %ld\n",
                        s_page);

        offset_t = (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CMCPGB_PAGE_SIZE_NBYTES - offset_t);

        CBYTES_BUF(&cbytes) = m_buff;
        CBYTES_LEN(&cbytes) = e_offset - s_offset;

        if(EC_FALSE == cmc_page_read_e(cmc_md, &cmcnp_key, &offset_t, max_len, &cbytes))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_read: "
                            "read page %ld, offset %ld, len %ld failed\n",
                            s_page, (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK)), max_len);
            return (EC_FALSE);
        }

        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_read: "
                        "read page %ld => offset %ld, len %ld\n",
                        s_page, offset_t, CBYTES_LEN(&cbytes));

        CMC_ASSERT(CBYTES_BUF(&cbytes) == m_buff);

        s_offset += CBYTES_LEN(&cbytes);
        m_buff   += CBYTES_LEN(&cbytes);
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cmc_file_write(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_file_write: cmc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;
    m_buff   = buff;

    s_page   = (s_offset >> CMCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_write: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CMCNP_KEY     cmcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES        cbytes;

        /*one page only*/
        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(s_page + 0);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CMCPGB_PAGE_SIZE_NBYTES - offset_t);

        CBYTES_BUF(&cbytes) = m_buff;
        CBYTES_LEN(&cbytes) = max_len;

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CMCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_write: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cmc_page_write_e(cmc_md, &cmcnp_key, &offset_t, max_len, &cbytes))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_write: "
                                "override page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_write: "
                            "override page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            if(EC_FALSE == cmc_page_write(cmc_md, &cmcnp_key, &cbytes))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_write: "
                                "write page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_write: "
                            "write page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        CMC_ASSERT(CBYTES_BUF(&cbytes) == m_buff);

        s_offset += CBYTES_LEN(&cbytes);
        m_buff   += CBYTES_LEN(&cbytes);
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  delete a file (POSIX style interface)
*
**/
EC_BOOL cmc_file_delete(CMC_MD *cmc_md, UINT32 *offset, const UINT32 dsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_file_delete: cmc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + dsize;

    s_page   = (s_offset >> CMCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                                        "offset %ld, dsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), dsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CMCNP_KEY     cmcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(s_page + 0);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CMCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*skip non-existence*/
        if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
        {
            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                            "page %ld absent, [%ld, %ld), offset %ld, len %ld in page\n",
                            s_page,
                            s_offset, e_offset,
                            offset_t, max_len);
            s_offset += max_len;
            continue;
        }

        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                        "mem hit page %ld, [%ld, %ld), offset %ld, len %ld in page\n",
                        s_page,
                        s_offset, e_offset,
                        offset_t, max_len);

        /*when partial delete, need the whole page exists*/
        if(0 < offset_t || CMCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            CMCNP_FNODE   cmcnp_fnode;
            UINT32        file_size;

            cmcnp_fnode_init(&cmcnp_fnode);

            /*found inconsistency*/
            if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), &cmcnp_key, &cmcnp_fnode))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_delete: "
                                "read page %ld failed, [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
                return (EC_FALSE);
            }

            file_size   = (UINT32)(((UINT32)CMCNP_FNODE_PAGENUM(&cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);

            if(file_size > offset_t + max_len)
            {
                /*do nothing*/
                dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                                "ignore page %ld (file size %ld > %ld + %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t, max_len,
                                s_offset, e_offset,
                                offset_t, max_len);
            }

            else if (file_size <= offset_t)
            {
                /*do nothing*/
                dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                                "ignore page %ld (file size %ld <= %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t,
                                s_offset, e_offset,
                                offset_t, max_len);
            }

            /*now: offset_t < file_size <= offset_t + max_len*/

            else if(0 == offset_t)
            {
                if(EC_FALSE == cmc_page_delete(cmc_md, &cmcnp_key))
                {
                    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_delete: "
                                    "delete page %ld failed, [%ld, %ld), offset %ld, len %ld in page\n",
                                    s_page,
                                    s_offset, e_offset,
                                    offset_t, max_len);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                                "delete page %ld done, [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
            }
            else
            {
                CMC_ASSERT(CMCPGB_PAGE_SIZE_NBYTES == (uint32_t)offset_t);
                CMCNP_FNODE_PAGENUM(&cmcnp_fnode) = (uint16_t)(offset_t >> CMCPGB_PAGE_SIZE_NBITS);

                if(EC_FALSE == cmcnp_update(CMC_MD_NP(cmc_md), &cmcnp_key, &cmcnp_fnode))
                {
                    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_delete: "
                                    "update page %ld failed (file size %ld => %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                    s_page,
                                    file_size, offset_t,
                                    s_offset, e_offset,
                                    offset_t, max_len);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                                "update page %ld done (file size %ld => %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t,
                                s_offset, e_offset,
                                offset_t, max_len);
            }
        }

        else
        {
            if(EC_FALSE == cmc_page_delete(cmc_md, &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_delete: "
                                "delete page %ld failed, [%ld, %ld), offset %ld, len %ld\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_delete: "
                            "delete page %ld done, [%ld, %ld), offset %ld, len %ld\n",
                            s_page,
                            s_offset, e_offset,
                            offset_t, max_len);
        }

        s_offset += max_len;
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  set file ssd dirty flag which means flush it to ssd later
*
**/
EC_BOOL cmc_file_set_ssd_dirty(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_file_set_ssd_dirty: cmc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;

    s_page   = (s_offset >> CMCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_set_ssd_dirty: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CMCNP_KEY     cmcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(s_page + 0);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CMCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CMCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_dirty: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cmcnp_set_ssd_dirty(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_dirty: "
                                "set ssd dirty flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_set_ssd_dirty: "
                            "set ssd dirty flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            /*check existing*/
            if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_dirty: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cmcnp_set_ssd_dirty(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_dirty: "
                                "set ssd dirty flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_set_ssd_dirty: "
                            "set ssd dirty flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        s_offset += max_len;
        (*offset) = s_offset;
    }

    return (EC_TRUE);
}

/**
*
*  unset file ssd dirty flag which means cmc should not flush it to ssd
*
**/
EC_BOOL cmc_file_set_ssd_not_dirty(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_file_set_ssd_not_dirty: cmc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;

    s_page   = (s_offset >> CMCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_set_ssd_not_dirty: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CMCNP_KEY     cmcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(s_page + 0);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CMCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CMCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_not_dirty: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cmcnp_set_ssd_not_dirty(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_not_dirty: "
                                "set ssd not dirty flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_set_ssd_not_dirty: "
                            "set ssd not dirty flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            /*check existing*/
            if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_not_dirty: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cmcnp_set_ssd_not_dirty(CMC_MD_NP(cmc_md), &cmcnp_key))
            {
                dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_set_ssd_not_dirty: "
                                "set ssd not dirty flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_set_ssd_not_dirty: "
                            "set ssd not dirty flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        s_offset += max_len;
        (*offset) = s_offset;
    }

    return (EC_TRUE);
}

/**
*
*  locate a page
*
**/
UINT8 *cmc_page_locate(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_FNODE  *cmcnp_fnode;
    CMCNP_INODE  *cmcnp_inode;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_locate: np was not open\n");
        return (NULL_PTR);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_locate: dn was not open\n");
        return (NULL_PTR);
    }

    cmcnp_fnode = cmcnp_locate(CMC_MD_NP(cmc_md), cmcnp_key);
    if(NULL_PTR == cmcnp_fnode)
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_page_locate: locate np failed\n");
        return (NULL_PTR);
    }

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    return cmcdn_node_locate(CMC_MD_DN(cmc_md),
                            CMCNP_INODE_DISK_NO(cmcnp_inode),
                            CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                            CMCNP_INODE_PAGE_NO(cmcnp_inode));
}

/**
*
*  write a page
*
**/
EC_BOOL cmc_page_write(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes)
{
    CMCNP_FNODE  *cmcnp_fnode;
    UINT32        page_num;
    UINT32        space_len;
    UINT32        data_len;
    uint32_t      path_hash;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_page_write: cmc is read-only\n");
        return (EC_FALSE);
    }

    cmcnp_fnode = __cmc_reserve_np(cmc_md, cmcnp_key);
    if(NULL_PTR == cmcnp_fnode)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_write: reserve np failed\n");

        return (EC_FALSE);
    }

    path_hash = cmcnp_key_hash(cmcnp_key);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cmcnp_fnode_init(cmcnp_fnode);

        if(do_log(SEC_0118_CMC, 1))
        {
            sys_log(LOGSTDOUT, "warn:cmc_page_write: write with zero len to dn where fnode is \n");
            cmcnp_fnode_print(LOGSTDOUT, cmcnp_fnode);
        }

        return (EC_TRUE);
    }

    /*note: when reserve space from data node, the length depends on cmcnp_key but not cbytes*/
    page_num  = (CMCNP_KEY_E_PAGE(cmcnp_key) - CMCNP_KEY_S_PAGE(cmcnp_key));
    space_len = (page_num << CMCPGB_PAGE_SIZE_NBITS);
    data_len  = DMIN(space_len, CBYTES_LEN(cbytes));/*xxx*/

    CMC_ASSERT(CMCPGB_PAGE_SIZE_NBYTES == data_len);

    /*when fnode is duplicate, do not reserve data node anymore*/
    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        if(EC_FALSE == __cmc_reserve_hash_dn(cmc_md, data_len, path_hash, cmcnp_fnode))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_write: reserve dn %ld bytes failed\n",
                            data_len);

            __cmc_release_np(cmc_md, cmcnp_key);

            return (EC_FALSE);
        }
    }
    else
    {
        /*when fnode is duplicate, update file size*/
        CMCNP_FNODE_PAGENUM(cmcnp_fnode) = (uint16_t)(data_len >> CMCPGB_PAGE_SIZE_NBITS);
    }

    if(EC_FALSE == cmc_export_dn(cmc_md, cbytes, cmcnp_fnode))
    {
        cmc_release_dn(cmc_md, cmcnp_fnode);

        __cmc_release_np(cmc_md, cmcnp_key);

        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_write: export content to dn failed\n");

        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_page_write: write to dn where fnode is \n");
        cmcnp_fnode_print(LOGSTDOUT, cmcnp_fnode);
    }

    return (EC_TRUE);
}

/**
*
*  read a page
*
**/
EC_BOOL cmc_page_read(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, CBYTES *cbytes)
{
    CMCNP_FNODE   cmcnp_fnode;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    cmcnp_fnode_init(&cmcnp_fnode);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_read: read start\n");

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_page_read: read from np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_read: read from np done\n");

    /*exception*/
    if(0 == CMCNP_FNODE_PAGENUM(&cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_page_read: read with zero len from np and fnode %p is \n", &cmcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmc_read_dn(cmc_md, &cmcnp_fnode, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_read: read from dn failed where fnode is \n");
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_page_read: read with size %ld done\n",
                            cbytes_len(cbytes));
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
    }
    return (EC_TRUE);
}

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a page at offset
*
**/
EC_BOOL cmc_page_write_e(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CMCNP_FNODE   cmcnp_fnode;
    uint16_t      file_old_page_num;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_page_write_e: cmc is read-only\n");
        return (EC_FALSE);
    }

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_write_e: read from np failed\n");
        return (EC_FALSE);
    }

    file_old_page_num = CMCNP_FNODE_PAGENUM(&cmcnp_fnode);

    if(EC_FALSE == cmc_write_e_dn(cmc_md, &cmcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    if(file_old_page_num != CMCNP_FNODE_PAGENUM(&cmcnp_fnode))
    {
        if(EC_FALSE == cmcnp_update(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_write_e: offset write to np failed\n");
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  read a page from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL cmc_page_read_e(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CMCNP_FNODE   cmcnp_fnode;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_read_e: read from np failed\n");
        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_page_read_e: read from np and fnode %p is \n",
                           &cmcnp_fnode);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
    }

    /*exception*/
    if(0 == CMCNP_FNODE_PAGENUM(&cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_page_read_e: read with zero len from np and fnode %p is \n", &cmcnp_fnode);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmc_read_e_dn(cmc_md, &cmcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_read_e: offset read from dn failed where fnode is\n");
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL cmc_export_dn(CMC_MD *cmc_md, const CBYTES *cbytes, const CMCNP_FNODE *cmcnp_fnode)
{
    const CMCNP_INODE *cmcnp_inode;

    UINT32   file_size;
    UINT32   offset;
    UINT32   data_len;
    //uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;


    file_size = (UINT32)(((UINT32)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);
    data_len  = DMIN(CBYTES_LEN(cbytes), file_size);

    CMC_ASSERT(data_len == CMCPGB_PAGE_SIZE_NBYTES);

    if(CMCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: CBYTES_LEN %u or CMCNP_FNODE_PAGENUM %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CMCNP_FNODE_PAGENUM(cmcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CMCPGB_PAGE_SIZE_NBITS));
    if(EC_FALSE == cmcdn_write_o(CMC_MD_DN(cmc_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    //dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_export_dn: write %ld bytes to disk %u block %u page %u done\n",
    //                    data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL cmc_write_dn(CMC_MD *cmc_md, const CBYTES *cbytes, CMCNP_FNODE *cmcnp_fnode)
{
    CMCNP_INODE *cmcnp_inode;

    uint32_t data_len;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_write_dn: cmc is read-only\n");
        return (EC_FALSE);
    }

    if(CMCPGB_SIZE_NBYTES <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cmcnp_fnode_init(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(EC_FALSE == cmcdn_write_p(CMC_MD_DN(cmc_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CMCNP_INODE_DISK_NO(cmcnp_inode)    = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = page_no;

    data_len = CBYTES_LEN(cbytes);
    CMC_ASSERT(CMCPGB_PAGE_SIZE_NBYTES == data_len);

    CMCNP_FNODE_PAGENUM(cmcnp_fnode) = (uint16_t)(data_len >> CMCPGB_PAGE_SIZE_NBITS);
    CMCNP_FNODE_REPNUM(cmcnp_fnode)  = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL cmc_read_dn(CMC_MD *cmc_md, const CMCNP_FNODE *cmcnp_fnode, CBYTES *cbytes)
{
    const CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    //dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CMC_0003);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CMC_0004);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcdn_read_p(CMC_MD_DN(cmc_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cmc_write_e_dn(CMC_MD *cmc_md, CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CMCNP_INODE *cmcnp_inode;

    UINT32   max_len_t;

    uint32_t file_size;
    uint32_t file_max_size;
    uint32_t offset_t;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_write_e_dn: cmc is read-only\n");
        return (EC_FALSE);
    }

    if(CMCPGB_SIZE_NBYTES <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CMCPGB_PAGE_SIZE_NBYTES - 1) >> CMCPGB_PAGE_SIZE_NBITS) << CMCPGB_PAGE_SIZE_NBITS);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == cmcdn_write_e(CMC_MD_DN(cmc_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    (*offset) += max_len_t;
    if((*offset) > file_size)
    {
        CMC_ASSERT(CMCPGB_PAGE_SIZE_NBYTES == (*offset));
        /*update file size info*/
        CMCNP_FNODE_PAGENUM(cmcnp_fnode) = (uint16_t)((*offset) >> CMCPGB_PAGE_SIZE_NBITS);
    }

    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cmc_read_e_dn(CMC_MD *cmc_md, const CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    const CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: due to offset %ld >= file size %u\n", (*offset), file_size);
        return (EC_FALSE);
    }

    offset_t = (uint32_t)(*offset);
    if(0 == max_len)
    {
        max_len_t = file_size - offset_t;
    }
    else
    {
        max_len_t = DMIN(max_len, file_size - offset_t);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CMC_0005);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CMC_0006);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < max_len_t)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: cbytes len %ld < max len %ld\n",
                        CBYTES_LEN(cbytes), max_len_t);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcdn_read_e(CMC_MD_DN(cmc_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: read %ld bytes from disk %u, block %u, offset %u failed\n",
                           max_len_t, disk_no, block_no, offset_t);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}


/**
*
*  delete a page
*
**/
EC_BOOL cmc_page_delete(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key)
{
    uint32_t     node_pos;

    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_page_delete: np was not open\n");
        return (EC_FALSE);
    }

    node_pos = cmcnp_search(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS == node_pos)
    {
        /*not found*/

        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_delete: cmc %p, not found key [%u, %u)\n",
                            cmc_md, CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));

        return (EC_TRUE);
    }

    if(EC_FALSE == cmcnp_umount_item(CMC_MD_NP(cmc_md), node_pos))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_delete: umount failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_delete: cmc %p, key [%u, %u) done\n",
                        cmc_md, CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));

    return (EC_TRUE);
}

/**
*
*  update a page
*
**/
EC_BOOL cmc_page_update(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes)
{
    CMC_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cmc_page_write(cmc_md, cmcnp_key, cbytes))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_update: write failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_update: write done\n");
        return (EC_TRUE);
    }

    /*file exist, update it*/
    if(EC_FALSE == cmc_page_delete(cmc_md, cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_update: delete old failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_update: delete old done\n");

    if(EC_FALSE == cmc_page_write(cmc_md, cmcnp_key, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_page_update: write new failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_page_update: write new done\n");

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cmc_file_num(CMC_MD *cmc_md, UINT32 *file_num)
{
    uint32_t     file_num_t;

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_num: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_file_num(CMC_MD_NP(cmc_md), &file_num_t))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_num: get file num of key failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != file_num)
    {
        (*file_num) = file_num_t;
    }
    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cmc_file_size(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, UINT32 *file_size)
{
    if(EC_FALSE == cmcnp_key_is_valid(cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_size: invalid key [%u, %u)\n",
                        CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_size: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_file_size(CMC_MD_NP(cmc_md), cmcnp_key, file_size))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_size: cmcnp mgr get size of key [%u, %u) failed\n",
                        CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_size: key [%u, %u), size %ld\n",
                    CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key), (*file_size));
    return (EC_TRUE);
}

/**
*
*  name node used ratio
*
**/
REAL cmc_used_ratio(CMC_MD *cmc_md)
{
    REAL    np_used_ratio;
    REAL    dn_used_ratio;

    np_used_ratio = 0.0;
    dn_used_ratio = 0.0;

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        np_used_ratio = cmcnp_used_ratio(CMC_MD_NP(cmc_md));
    }

    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        dn_used_ratio = cmcdn_used_ratio(CMC_MD_DN(cmc_md));
    }

    return DMAX(np_used_ratio, dn_used_ratio);
}

/**
*
*  name node deg ratio
*
**/
REAL cmc_deg_ratio(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        return cmcnp_deg_ratio(CMC_MD_NP(cmc_md));
    }

    return (0.0);
}

/**
*
*  name node deg num
*
**/
uint32_t cmc_deg_num(CMC_MD *cmc_md)
{
    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        return cmcnp_deg_num(CMC_MD_NP(cmc_md));
    }

    return (0);
}

/**
*
*  search in current name node
*
**/
EC_BOOL cmc_search(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key)
{
    if(EC_FALSE == cmcnp_key_is_valid(cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_search: invalid key [%u, %u)\n",
                        CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_search: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_has_key(CMC_MD_NP(cmc_md), cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 7)(LOGSTDOUT, "warn:cmc_search: miss key [%u, %u)\n",
                        CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));
        return (EC_FALSE);
    }

    if(CMCNPRB_ERR_POS == cmcnp_search(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_search: search failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL cmc_recycle(CMC_MD *cmc_md, const UINT32 max_num, UINT32 *complete_num)
{
    CMCNP_RECYCLE_DN cmcnp_recycle_dn;
    UINT32           complete_recycle_num;

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_recycle: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_recycle: cmc is read-only\n");
        return (EC_FALSE);
    }

    CMCNP_RECYCLE_DN_ARG1(&cmcnp_recycle_dn)   = (void *)cmc_md;
    CMCNP_RECYCLE_DN_FUNC(&cmcnp_recycle_dn)   = (CMCNP_RECYCLE_DN_FUNC)cmc_release_dn;

    complete_recycle_num = 0;/*initialization*/

    if(EC_FALSE == cmcnp_recycle(CMC_MD_NP(cmc_md),  max_num, NULL_PTR, &cmcnp_recycle_dn, &complete_recycle_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_recycle: recycle np failed\n");
        return (EC_FALSE);
    }

    if(0 < complete_recycle_num)
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "[DEBUG] cmc_recycle: recycle complete %ld\n",
                                            complete_recycle_num);
    }
    if(NULL_PTR != complete_num)
    {
        (*complete_num) += complete_recycle_num;
    }
    return (EC_TRUE);
}

/**
*
*  retire files
*
**/
EC_BOOL cmc_retire(CMC_MD *cmc_md, const UINT32 max_num, UINT32 *complete_num)
{
    UINT32      complete_retire_num;

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_retire: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_retire: cmc is read-only\n");
        return (EC_FALSE);
    }

    complete_retire_num = 0;/*initialization*/

    cmcnp_retire(CMC_MD_NP(cmc_md), CMC_SCAN_RETIRE_MAX_NUM, max_num, &complete_retire_num);

    if(0 < complete_retire_num)
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "[DEBUG] cmc_retire: retire done where complete %ld\n",
                                            complete_retire_num);
    }

    if(NULL_PTR != complete_num)
    {
        (*complete_num) += complete_retire_num;
    }

    return (EC_TRUE);
}


/**
*
*  degrade files
*
**/
EC_BOOL cmc_degrade(CMC_MD *cmc_md, const UINT32 max_num, UINT32 *complete_num)
{
    UINT32      complete_degrade_num;

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_degrade: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cmc_is_read_only(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "error:cmc_degrade: cmc is read-only\n");
        return (EC_FALSE);
    }

    complete_degrade_num = 0;/*initialization*/

    cmcnp_degrade(CMC_MD_NP(cmc_md), CMC_SCAN_DEGRADE_MAX_NUM, max_num, &complete_degrade_num);

    if(0 < complete_degrade_num)
    {
        dbg_log(SEC_0118_CMC, 3)(LOGSTDOUT, "[DEBUG] cmc_degrade: degrade done where complete %ld\n",
                                            complete_degrade_num);
    }

    if(NULL_PTR != complete_num)
    {
        (*complete_num) += complete_degrade_num;
    }

    return (EC_TRUE);
}

EC_BOOL cmc_set_degrade_callback(CMC_MD *cmc_md, CMCNP_DEGRADE_CALLBACK func, void *arg)
{
    if(NULL_PTR != cmc_md)
    {
        cmcnp_degrade_cb_set(CMC_MD_NP_DEGRADE_CB(cmc_md), func, arg);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL cmc_set_retire_callback(CMC_MD *cmc_md, CMCNP_RETIRE_CALLBACK func, void *arg)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_set_retire_callback: np was not open\n");
        return (EC_FALSE);
    }

    return cmcnp_set_retire_callback(CMC_MD_NP(cmc_md), func, arg);
}


/**
*
*  show name node
*
*
**/
EC_BOOL cmc_show_np(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cmc_show_np_lru_list(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print_lru_list(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cmc_show_np_del_list(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print_del_list(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show name node DEG
*
*
**/
EC_BOOL cmc_show_np_deg_list(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print_deg_list(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show name node BITMAP
*
*
**/
EC_BOOL cmc_show_np_bitmap(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print_bitmap(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show cmcdn info if it is dn
*
*
**/
EC_BOOL cmc_show_dn(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcdn_print(log, CMC_MD_DN(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show all files
*
**/

EC_BOOL cmc_show_files(const CMC_MD *cmc_md, LOG *log)
{
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_show_files: np was not open\n");
        return (EC_FALSE);
    }

    cmcnp_walk(CMC_MD_NP(cmc_md), (CMCNPRB_WALKER)cmcnp_file_print, (void *)log);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_show_files: walk cmcnp done\n");
    return (EC_TRUE);
}




#ifdef __cplusplus
}
#endif/*__cplusplus*/

