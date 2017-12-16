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

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "log.h"
#include "cmpic.inc"
#include "cdbgcode.h"
#include "ccode.h"

EC_BOOL cdbgcode_pack_uint32(const UINT32 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);

    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        UINT8 * pch;
        UINT32  ch_idx;

        pch = (UINT8 *)(in_buff + data_idx);

        for(ch_idx = 0; ch_idx < sizeof(UINT32); ch_idx ++)
        {
            if(this_pos >= out_buff_max_len)
            {
                dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_pack_uint32: overflow where pos = %ld and out_buff_max_len = %ld\n", this_pos, out_buff_max_len);
                return (EC_FALSE);
            }

            out_buff[ this_pos ++ ] = *(pch ++);
        }
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_uint32_size(const UINT32 data_num, UINT32 *size)
{
    (*size) += (data_num * sizeof(UINT32));
    return (EC_TRUE);
}

EC_BOOL cdbgcode_unpack_uint32(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *out_buff, const UINT32 data_num)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        if(this_pos >= in_buff_max_len)
        {
            dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_unpack_uint32: overflow where pos = %ld and in_buff_max_len = %ld\n", this_pos, in_buff_max_len);
            return (EC_FALSE);
        }

        *(out_buff + data_idx) = *(UINT32 *)(in_buff + this_pos);

        this_pos += sizeof(UINT32);
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_uint16(const UINT16 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        UINT8 * pch;
        UINT32  ch_idx;

        pch = (UINT8 *)(in_buff + data_idx);

        for(ch_idx = 0; ch_idx < sizeof(UINT16); ch_idx ++)
        {
            if(this_pos >= out_buff_max_len)
            {
                dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_pack_uint16: overflow where pos = %ld and out_buff_max_len = %ld\n", this_pos, out_buff_max_len);
                return (EC_FALSE);
            }

            out_buff[ this_pos ++ ] = *(pch ++);
        }
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_uint16_size(const UINT32 data_num, UINT32 *size)
{
    (*size) += (data_num * sizeof(UINT16));
    return (EC_TRUE);
}

EC_BOOL cdbgcode_unpack_uint16(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT16 *out_buff, const UINT32 data_num)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        if(this_pos >= in_buff_max_len)
        {
            dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_unpack_uint16: overflow where pos = %ld and in_buff_max_len = %ld\n", this_pos, in_buff_max_len);
            return (EC_FALSE);
        }

        *(out_buff + data_idx) = *(UINT16 *)(in_buff + this_pos);

        this_pos += sizeof(UINT16);
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_uint8(const UINT8 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        if(this_pos >= out_buff_max_len)
        {
            dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_pack_uint8: overflow where pos = %ld and out_buff_max_len = %ld\n", this_pos, out_buff_max_len);
            return (EC_FALSE);
        }
        out_buff[ this_pos ++ ] = *(in_buff + data_idx);
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_uint8_size(const UINT32 data_num, UINT32 *size)
{
    (*size) += (data_num * sizeof(UINT8));
    return (EC_TRUE);
}

EC_BOOL cdbgcode_unpack_uint8(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *out_buff, const UINT32 data_num)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        if(this_pos >= in_buff_max_len)
        {
            dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_unpack_uint8: overflow where pos = %ld and in_buff_max_len = %ld\n", this_pos, in_buff_max_len);
            return (EC_FALSE);
        }

        *(out_buff + data_idx) = *(UINT8 *)(in_buff + this_pos);

        this_pos += sizeof(UINT8);
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_real(const REAL *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        UINT8 * pch;
        UINT32  ch_idx;

        pch = (UINT8 *)(in_buff + data_idx);

        for(ch_idx = 0; ch_idx < sizeof(REAL); ch_idx ++)
        {
            if(this_pos >= out_buff_max_len)
            {
                dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_pack_real: overflow where pos = %ld and out_buff_max_len = %ld\n", this_pos, out_buff_max_len);
                return (EC_FALSE);
            }

            out_buff[ this_pos ++ ] = *(pch ++);
        }
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack_real_size(const UINT32 data_num, UINT32 *size)
{
    (*size) += (data_num * sizeof(REAL));
    return (EC_TRUE);
}

EC_BOOL cdbgcode_unpack_real(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, REAL *out_buff, const UINT32 data_num)
{
    UINT32 data_idx;
    UINT32 this_pos;

    this_pos = (*position);
    for(data_idx = 0; data_idx < data_num; data_idx ++)
    {
        if(this_pos >= in_buff_max_len)
        {
            dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_unpack_real: overflow where pos = %ld and in_buff_max_len = %ld\n", this_pos, in_buff_max_len);
            return (EC_FALSE);
        }

        *(out_buff + data_idx) = *(REAL *)(in_buff + this_pos);

        this_pos += sizeof(REAL);
    }

    (*position) = this_pos;
    return (EC_TRUE);
}

EC_BOOL cdbgcode_pack(const UINT8 *in_buff, const UINT32 data_num, const UINT32 data_type, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position, const UINT32 comm)
{
    switch(data_type)
    {
        case CMPI_ULONG:
            return cdbgcode_pack_uint32((UINT32 *)in_buff, data_num, out_buff, out_buff_max_len, position);
        case CMPI_USHORT:
            return cdbgcode_pack_uint16((UINT16 *)in_buff, data_num, out_buff, out_buff_max_len, position);
        case CMPI_UCHAR:
            return cdbgcode_pack_uint8((UINT8 *)in_buff, data_num, out_buff, out_buff_max_len, position);
        case CMPI_REAL:
            return cdbgcode_pack_real((REAL *)in_buff, data_num, out_buff, out_buff_max_len, position);
    }

    dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_pack: unknown data_type %ld\n", data_type);
    return (EC_FALSE);
}

EC_BOOL cdbgcode_unpack(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *out_buff, const UINT32 data_num, const UINT32 data_type, const UINT32 comm)
{
    switch(data_type)
    {
        case CMPI_ULONG:
            return cdbgcode_unpack_uint32(in_buff, in_buff_max_len, position, (UINT32 *)out_buff, data_num);
        case CMPI_USHORT:
            return cdbgcode_unpack_uint16(in_buff, in_buff_max_len, position, (UINT16 *)out_buff, data_num);
        case CMPI_UCHAR:
            return cdbgcode_unpack_uint8(in_buff, in_buff_max_len, position, (UINT8 *)out_buff, data_num);
        case CMPI_REAL:
            return cdbgcode_unpack_real(in_buff, in_buff_max_len, position, (REAL *)out_buff, data_num);
    }

    dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_unpack: unknown data_type %ld\n", data_type);
    return (EC_FALSE);
}

EC_BOOL cdbgcode_pack_size(const UINT32 data_num, const UINT32 data_type, UINT32 *size, const UINT32 comm)
{
    switch(data_type)
    {
        case CMPI_ULONG:
            return cdbgcode_pack_uint32_size(data_num, size);
        case CMPI_USHORT:
            return cdbgcode_pack_uint16_size(data_num, size);
        case CMPI_UCHAR:
            return cdbgcode_pack_uint8_size(data_num, size);
        case CMPI_REAL:
            return cdbgcode_pack_real_size(data_num, size);
    }

    dbg_log(SEC_0042_CDBGCODE, 0)(LOGSTDOUT, "error:cdbgcode_pack_size: unknown data_type %ld\n", data_type);
    return (EC_FALSE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

