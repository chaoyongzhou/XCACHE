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

#include "type.h"
#include "mm.h"

#include "carray.h"
#include "cindex.h"

#include "cbc.h"

#include "log.h"


static CARRAY *g_cbc = NULL_PTR;

static void cbc_data_cleaner(void *data)
{
    if(data)
    {
        SAFE_FREE(data, LOC_CBC_0001);
    }
    return;
}

EC_BOOL cbc_new(const UINT32 size)
{
    if(NULL_PTR == g_cbc)
    {
        g_cbc = carray_new(size, NULL_PTR, LOC_CBC_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cbc_free()
{
    if(NULL_PTR != g_cbc)
    {
        cbc_md_unreg_all();
        carray_free(g_cbc, LOC_CBC_0003);
        g_cbc = NULL_PTR;
    }
    return (EC_TRUE);
}

UINT32 cbc_size()
{
    if(NULL_PTR == g_cbc)
    {
        return (0);
    }
    return carray_size(g_cbc);
}

EC_BOOL cbc_md_reg(const UINT32 md_type, const UINT32 md_capaciy)
{
    CINDEX *md_cindex;

    if(NULL_PTR == g_cbc)
    {
        cbc_new(MM_END);
    }
    
    CARRAY_LOCK(g_cbc, LOC_CBC_0004);
    if(md_type >= carray_size(g_cbc))
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_reg: md_type %ld overflow the cbc size %ld", md_type, carray_size(g_cbc));
        CARRAY_UNLOCK(g_cbc, LOC_CBC_0005);
        return (EC_FALSE);
    }

    md_cindex = (CINDEX *)carray_get_no_lock(g_cbc, md_type);
    if(NULL_PTR != md_cindex)
    {
        dbg_log(SEC_0091_CBC, 9)(LOGSTDOUT, "[DEBUG] cbc_md_reg: md_type %ld has already registered\n", md_type);
        CARRAY_UNLOCK(g_cbc, LOC_CBC_0006);
        return (EC_FALSE);
    }

    md_cindex = cindex_new(md_capaciy, MM_UINT32, LOC_CBC_0007);/*note: the data item type is (void *) */
    if(NULL_PTR == md_cindex)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_reg: failed to register md_type %ld\n", md_type);
        CARRAY_UNLOCK(g_cbc, LOC_CBC_0008);
        return (EC_FALSE);
    }

    carray_set_no_lock(g_cbc, md_type, md_cindex);
    CARRAY_UNLOCK(g_cbc, LOC_CBC_0009);

    dbg_log(SEC_0091_CBC, 9)(LOGSTDOUT, "[DEBUG] cbc_md_reg: reg type %ld, capacity %ld\n", md_type, md_capaciy);
    return (EC_TRUE);
}

EC_BOOL cbc_md_unreg(const UINT32 md_type)
{
    CINDEX *md_cindex;

    if(NULL_PTR == g_cbc)
    {
        return (EC_FALSE);
    }

    CARRAY_LOCK(g_cbc, LOC_CBC_0010);
    md_cindex = (CINDEX *)carray_erase(g_cbc, md_type);
    if(NULL_PTR != md_cindex)
    {
        cindex_clean(md_cindex, cbc_data_cleaner, LOC_CBC_0011);
        cindex_free(md_cindex, LOC_CBC_0012);
    }
    CARRAY_UNLOCK(g_cbc, LOC_CBC_0013);
    //dbg_log(SEC_0091_CBC, 9)(LOGSTDOUT, "[DEBUG] cbc_md_unreg: unreg type %ld\n", md_type);
    return (EC_TRUE);
}

EC_BOOL cbc_md_unreg_all()
{
    UINT32 md_type;

    if(NULL_PTR == g_cbc)
    {
        return (EC_FALSE);
    }
    
    for(md_type = 0; md_type < carray_size(g_cbc); md_type ++)
    {
        cbc_md_unreg(md_type);
    }
    return (EC_TRUE);
}

UINT32 cbc_md_capacity(const UINT32 md_type)
{
    CINDEX *md_cindex;

    if(NULL_PTR == g_cbc)
    {
        return (0);
    }    

    md_cindex = (CINDEX *)carray_get(g_cbc, md_type);
    if(NULL_PTR == md_cindex)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDERR, "cbc_md_capacity: md_type %ld is not registered in CBC\n", md_type);
        return (0);
    }

    return cindex_capacity(md_cindex);
}

UINT32 cbc_md_num(const UINT32 md_type)
{
    CINDEX *md_cindex;

    md_cindex = (CINDEX *)carray_get(g_cbc, md_type);
    if(NULL_PTR == md_cindex)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDERR, "cbc_md_num: md_type %ld is not registered in CBC\n", md_type);
        return (0);
    }

    return cindex_size(md_cindex);
}

void *cbc_md_get(const UINT32 md_type, const UINT32 pos)
{
    CINDEX *md_cindex;
    if(NULL_PTR == g_cbc)
    {
        return (NULL_PTR);
    }
    
    md_cindex = (CINDEX *)carray_get(g_cbc, md_type);
    if(0 == md_cindex)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDERR, "cbc_md_get: md_type %ld is not registered in CBC\n", md_type);
        return (NULL_PTR);
    }
    return cindex_spy(md_cindex, pos);
}

/**
*
* strategy is to push a new one to cindex if free position available,
* otherwise, reuse an old one if exist; at last, expand cindex
*
**/
UINT32 cbc_md_add(const UINT32 md_type, const void *md)
{
    CINDEX *md_cindex;
    UINT32 pos;

    if(NULL_PTR == g_cbc)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_add: cbc not initialized\n");
        return (CMPI_ERROR_MODI);
    }

    md_cindex = (CINDEX *)carray_get(g_cbc, md_type);
    if(NULL_PTR == md_cindex)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_add: md_type %ld was not registered\n", md_type);
        return (CMPI_ERROR_MODI);
    }

    pos = cindex_reserve(md_cindex, md);
    if(CINDEX_ERR_POS == pos)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_add: failed to reserve index for md %lx with type %ld\n", md, md_type);
        return (CMPI_ERROR_MODI);
    }

    return (pos);
}

void * cbc_md_del(const UINT32 md_type, const UINT32 pos)
{
    CINDEX *md_cindex;
    void *md;

    if(NULL_PTR == g_cbc)
    {
        return (NULL_PTR);
    }

    md_cindex = (CINDEX *)carray_get(g_cbc, md_type);
    if(NULL_PTR == md_cindex)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_del: md_type %ld was not registered\n", md_type);
        return (NULL_PTR);
    }

    md = cindex_release(md_cindex, pos);
    if(NULL_PTR == md)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "error:cbc_md_del: md with md_type %ld at pos %ld does not exist\n", md_type, md);
        return (NULL_PTR);
    }
    return (md);
}

UINT32 cbc_md_new(const UINT32 md_type, const UINT32 sizeof_md)
{
    void *md;
    UINT32 pos;

    md = SAFE_MALLOC(sizeof_md, LOC_CBC_0014);
    if(NULL_PTR == md)
    {
        return (CMPI_ERROR_MODI);
    }

    pos = cbc_md_add(md_type, md);
    if(CMPI_ERROR_MODI == pos)
    {
        SAFE_FREE(md, LOC_CBC_0015);
        return (CMPI_ERROR_MODI);
    }
    return pos;
}

EC_BOOL cbc_md_free(const UINT32 md_type, const UINT32 pos)
{
    void *md;

    md = cbc_md_del(md_type, pos);
    if(NULL_PTR != md)
    {
        SAFE_FREE(md, LOC_CBC_0016);
    }
    return (EC_TRUE);
}

UINT32 cbc_sum()
{
    UINT32 md_type;
    CINDEX *md_cindex;
    UINT32 md_sum;

    if(NULL_PTR == g_cbc)
    {
        dbg_log(SEC_0091_CBC, 0)(LOGSTDOUT, "cbc_sum: error:g_cbc is null\n");
        return (0);
    }

    CARRAY_LOCK(g_cbc, LOC_CBC_0017);
    md_sum = 0;
    for(md_type = 0; md_type < cbc_size(); md_type ++)
    {
        md_cindex = (CINDEX *)carray_get_no_lock(g_cbc, md_type);
        if(NULL_PTR == md_cindex)
        {
            continue;
        }
        md_sum += cindex_size(md_cindex);
    }
    CARRAY_UNLOCK(g_cbc, LOC_CBC_0018);
    return (md_sum);
}

EC_BOOL cbc_print(LOG *log)
{
    UINT32 md_type;
    CINDEX *md_cindex;

    CARRAY_LOCK(g_cbc, LOC_CBC_0019);

    sys_log(log, "---------------------------------- cbc_print beg ------------------------\n");
    if(NULL_PTR == g_cbc)
    {
        sys_log(log, "cbc_print: error:g_cbc is null\n");
        CARRAY_UNLOCK(g_cbc, LOC_CBC_0020);
        return (EC_FALSE);
    }

    sys_log(log, "cbc_print: cbc size: %ld\n", cbc_size());
    for(md_type = 0; md_type < cbc_size(); md_type ++)
    {
        md_cindex = (CINDEX *)carray_get_no_lock(g_cbc, md_type);
        if(NULL_PTR == md_cindex)
        {
            continue;
        }

        sys_log(log, "cbc_print: md_type: %ld, md_cindex: %lx\n", md_type, md_cindex);
        cindex_print(log, md_cindex, 0);
    }
    sys_log(log, "---------------------------------- cbc_print end ------------------------\n");
    CARRAY_UNLOCK(g_cbc, LOC_CBC_0021);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
