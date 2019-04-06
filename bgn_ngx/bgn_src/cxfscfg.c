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

#include "cxfsnp.inc"
#include "chashalgo.h"

#include "camd.h"

#include "cxfscfg.h"

EC_BOOL cxfszone_init(CXFSZONE *cxfszone)
{
    CXFSZONE_S_OFFSET(cxfszone)          = ERR_OFFSET;
    CXFSZONE_E_OFFSET(cxfszone)          = ERR_OFFSET;

    return (EC_TRUE);
}

EC_BOOL cxfszone_clean(CXFSZONE *cxfszone)
{
    CXFSZONE_S_OFFSET(cxfszone)          = ERR_OFFSET;
    CXFSZONE_E_OFFSET(cxfszone)          = ERR_OFFSET;

    return (EC_TRUE);
}

void cxfszone_print(LOG *log, const CXFSZONE *cxfszone) {

    sys_print(log, "cxfszone_print: cxfszone %p, "
                   "range [%ld, %ld)\n",
                   cxfszone,
                   CXFSZONE_S_OFFSET(cxfszone), CXFSZONE_E_OFFSET(cxfszone));

   return;
}

EC_BOOL cxfscfg_init(CXFSCFG *cxfscfg)
{
    CXFSCFG_MAGIC(cxfscfg)                = 0;

    CXFSCFG_SATA_DISK_SIZE(cxfscfg)       = 0;
    CXFSCFG_SATA_DISK_OFFSET(cxfscfg)     = ERR_OFFSET;

    CXFSCFG_NP_SIZE(cxfscfg)              = 0;
    CXFSCFG_NP_MODEL(cxfscfg)             = CXFSNP_ERR_MODEL;
    CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg) = CHASH_ERR_ALGO_ID;
    CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)      = 0;
    CXFSCFG_NP_MAX_NUM(cxfscfg)           = 0;

    CXFSCFG_DN_ZONE_SIZE(cxfscfg)         = 0;

    CXFSCFG_OP_S_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_OP_E_OFFSET(cxfscfg)          = ERR_OFFSET;

    cxfszone_init(CXFSCFG_NP_ZONE(cxfscfg, 0));
    cxfszone_init(CXFSCFG_NP_ZONE(cxfscfg, 1));
    CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg)   = 0;
    CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)     = ERR_OFFSET;
    CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg)     = ERR_OFFSET;

    cxfszone_init(CXFSCFG_DN_ZONE(cxfscfg, 0));
    cxfszone_init(CXFSCFG_DN_ZONE(cxfscfg, 1));
    CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg)   = 0;
    CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg)     = ERR_OFFSET;
    CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg)     = ERR_OFFSET;

    CXFSCFG_SSD_DISK_SIZE(cxfscfg)        = 0;
    CXFSCFG_SSD_DISK_OFFSET(cxfscfg)      = ERR_OFFSET;

    CXFSCFG_OP_DUMP_TIME_MSEC(cxfscfg)    = 0;
    return (EC_TRUE);
}

EC_BOOL cxfscfg_clean(CXFSCFG *cxfscfg)
{
    CXFSCFG_MAGIC(cxfscfg)                = 0;

    CXFSCFG_SATA_DISK_SIZE(cxfscfg)       = 0;
    CXFSCFG_SATA_DISK_OFFSET(cxfscfg)     = ERR_OFFSET;

    CXFSCFG_NP_SIZE(cxfscfg)              = 0;
    CXFSCFG_NP_MODEL(cxfscfg)             = CXFSNP_ERR_MODEL;
    CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg) = CHASH_ERR_ALGO_ID;
    CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)      = 0;
    CXFSCFG_NP_MAX_NUM(cxfscfg)           = 0;

    CXFSCFG_DN_ZONE_SIZE(cxfscfg)         = 0;

    CXFSCFG_OP_S_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_OP_E_OFFSET(cxfscfg)          = ERR_OFFSET;

    cxfszone_clean(CXFSCFG_NP_ZONE(cxfscfg, 0));
    cxfszone_clean(CXFSCFG_NP_ZONE(cxfscfg, 1));
    CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg)   = 0;
    CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)     = ERR_OFFSET;
    CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg)     = ERR_OFFSET;

    cxfszone_clean(CXFSCFG_DN_ZONE(cxfscfg, 0));
    cxfszone_clean(CXFSCFG_DN_ZONE(cxfscfg, 1));
    CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg)   = 0;
    CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg)     = ERR_OFFSET;
    CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg)     = ERR_OFFSET;

    CXFSCFG_SSD_DISK_SIZE(cxfscfg)        = 0;
    CXFSCFG_SSD_DISK_OFFSET(cxfscfg)      = ERR_OFFSET;

    CXFSCFG_OP_DUMP_TIME_MSEC(cxfscfg)    = 0;
    return (EC_TRUE);
}

void cxfscfg_print(LOG *log, const CXFSCFG *cxfscfg)
{
    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "magic %#lx\n",
                   cxfscfg,
                   CXFSCFG_MAGIC(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "sata: size %ld, offset %ld\n",
                   cxfscfg,
                   CXFSCFG_SATA_DISK_SIZE(cxfscfg),
                   CXFSCFG_SATA_DISK_OFFSET(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "np: size %ld, model %u, algo %u, "
                   "item max num %u, np max num %u\n",
                   cxfscfg,
                   CXFSCFG_NP_SIZE(cxfscfg),
                   CXFSCFG_NP_MODEL(cxfscfg),
                   CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg),
                   CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg),
                   CXFSCFG_NP_MAX_NUM(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "dn: size %ld\n",
                   cxfscfg,
                   CXFSCFG_DN_ZONE_SIZE(cxfscfg));

    /*op*/
    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "op: range [%ld, %ld)\n",
                   cxfscfg,
                   CXFSCFG_OP_S_OFFSET(cxfscfg), CXFSCFG_OP_E_OFFSET(cxfscfg));

    /*np zone*/
    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "np zone: range [%ld, %ld), active %ld\n",
                   cxfscfg,
                   CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg), CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg),
                   CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "np zone:[0]\n",
                   cxfscfg);
    cxfszone_print(log, CXFSCFG_NP_ZONE(cxfscfg, 0));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "np zone:[1]\n",
                   cxfscfg);
    cxfszone_print(log, CXFSCFG_NP_ZONE(cxfscfg, 1));

    /*dn zone*/
    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "dn zone: range [%ld, %ld), active %ld\n",
                   cxfscfg,
                   CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg), CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg),
                   CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "dn zone:[0]\n",
                   cxfscfg);
    cxfszone_print(log, CXFSCFG_DN_ZONE(cxfscfg, 0));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "dn zone:[1]\n",
                   cxfscfg);
    cxfszone_print(log, CXFSCFG_DN_ZONE(cxfscfg, 1));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "ssd: size %ld, offset %ld\n",
                   cxfscfg,
                   CXFSCFG_SSD_DISK_SIZE(cxfscfg),
                   CXFSCFG_SSD_DISK_OFFSET(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "op dump time: %lu [%s]\n",
                   cxfscfg,
                   CXFSCFG_OP_DUMP_TIME_MSEC(cxfscfg),
                   CXFSCFG_OP_DUMP_TIME_MSEC_STR(cxfscfg));
   return;
}

EC_BOOL cxfscfg_load(CXFSCFG *cxfscfg, int fd)
{
    void       *data; /*256KB*/
    UINT32      offset;

    data = c_memalign_new(CXFSCFG_SIZE, CXFSCFG_ALIGNMENT);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "error:cxfscfg_load: memory insufficient\n");
        return (EC_FALSE);
    }

    /*load config*/
    offset = 0;
    if(EC_FALSE == c_file_pread(fd, &offset, CXFSCFG_SIZE, (UINT8 *)data))
    {
        dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "error:cxfscfg_load: load cfg failed\n");

        c_memalign_free(data);
        return (EC_FALSE);
    }

    BCOPY(data, cxfscfg, sizeof(CXFSCFG));

    c_memalign_free(data);

    return (EC_TRUE);
}

EC_BOOL cxfscfg_flush(const CXFSCFG *cxfscfg, int fd)
{
    void       *data; /*256KB*/
    UINT32      offset;

    data = c_memalign_new(CXFSCFG_SIZE, CXFSCFG_ALIGNMENT);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "error:cxfscfg_flush: memory insufficient\n");
        return (EC_FALSE);
    }

    BCOPY(cxfscfg, data, sizeof(CXFSCFG));

    /*flush config*/
    offset = 0;
    if(EC_FALSE == c_file_pwrite(fd, &offset, CXFSCFG_SIZE, (UINT8 *)data))
    {
        dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "error:cxfscfg_flush: flush cfg failed\n");

        c_memalign_free(data);
        return (EC_FALSE);
    }

    c_memalign_free(data);

    dbg_log(SEC_0205_CXFSCFG, 9)(LOGSTDOUT, "[DEBUG] cxfscfg_flush: "
                                            "flush %ld bytes to offset %ld done\n",
                                            (UINT32)CXFSCFG_SIZE, (UINT32)0);

    return (EC_TRUE);
}

EC_BOOL cxfscfg_dump(const CXFSCFG *cxfscfg, CAMD_MD *camd_md)
{
    UINT32           offset;

    if(NULL_PTR == camd_md)
    {
        dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "error:cxfscfg_dump: "
                                                "camd is null\n");
        return (EC_FALSE);
    }

    /*dump config*/
    offset = 0;

    if(EC_FALSE == camd_file_write_dio(camd_md, &offset, sizeof(CXFSCFG), (UINT8 *)cxfscfg))
    {
        dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "error:cxfscfg_dump: "
                                                "dump cxfscfg failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0205_CXFSCFG, 0)(LOGSTDOUT, "[DEBUG] cxfscfg_dump: "
                                            "dump cxfscfg done\n");
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

