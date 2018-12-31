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

#include "cxfscfg.h"

EC_BOOL cxfscfg_init(CXFSCFG *cxfscfg)
{
    CXFSCFG_MAGIC(cxfscfg)                = 0;
    CXFSCFG_SATA_DISK_SIZE(cxfscfg)       = 0;

    CXFSCFG_NP_S_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_NP_E_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_NP_SIZE(cxfscfg)              = 0;
    CXFSCFG_NP_MODEL(cxfscfg)             = CXFSNP_ERR_MODEL;
    CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg) = CHASH_ERR_ALGO_ID;
    CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)      = 0;
    CXFSCFG_NP_MAX_NUM(cxfscfg)           = 0;

    CXFSCFG_DN_S_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_DN_E_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_DN_SIZE(cxfscfg)              = 0;

    return (EC_TRUE);
}

EC_BOOL cxfscfg_clean(CXFSCFG *cxfscfg)
{
    CXFSCFG_MAGIC(cxfscfg)                = 0;
    CXFSCFG_SATA_DISK_SIZE(cxfscfg)       = 0;

    CXFSCFG_NP_S_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_NP_E_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_NP_SIZE(cxfscfg)              = 0;
    CXFSCFG_NP_MODEL(cxfscfg)             = CXFSNP_ERR_MODEL;
    CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg) = CHASH_ERR_ALGO_ID;
    CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)      = 0;
    CXFSCFG_NP_MAX_NUM(cxfscfg)           = 0;

    CXFSCFG_DN_S_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_DN_E_OFFSET(cxfscfg)          = ERR_OFFSET;
    CXFSCFG_DN_SIZE(cxfscfg)              = 0;

    return (EC_TRUE);
}

void cxfscfg_print(LOG *log, const CXFSCFG *cxfscfg)
{
    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "magic %#lx, sata disk size %ld\n",
                   cxfscfg,
                   CXFSCFG_MAGIC(cxfscfg),
                   CXFSCFG_SATA_DISK_SIZE(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "np: range [%ld, %ld), size %ld, model %u, algo %u, "
                   "item max num %u, np max num %u\n",
                   cxfscfg,
                   CXFSCFG_NP_S_OFFSET(cxfscfg), CXFSCFG_NP_E_OFFSET(cxfscfg),
                   CXFSCFG_NP_SIZE(cxfscfg),
                   CXFSCFG_NP_MODEL(cxfscfg),
                   CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg),
                   CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg),
                   CXFSCFG_NP_MAX_NUM(cxfscfg));

    sys_print(log, "cxfscfg_print: cxfscfg %p, "
                   "dn: range [%ld, %ld), size %ld\n",
                   cxfscfg,
                   CXFSCFG_DN_S_OFFSET(cxfscfg), CXFSCFG_DN_E_OFFSET(cxfscfg),
                   CXFSCFG_DN_SIZE(cxfscfg));
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

#ifdef __cplusplus
}
#endif/*__cplusplus*/

