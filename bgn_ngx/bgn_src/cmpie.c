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
#include <time.h>

#include "bgnctrl.h"
#include "type.h"

#include "mm.h"

#include "log.h"

#include "debug.h"

#include "clist.h"
#include "cvector.h"

#include "cstring.h"

#include "mod.h"
#include "task.h"

#include "super.h"

#include "cmpic.inc"
#include "cmpie.h"

#include "cdbgcode.h"
#include "cbytecode.h"
#include "ccode.h"

#include "tcnode.h"

#include "kbuff.h"
#include "crfs.h"
#include "crfsnp.h"
#include "crfsdn.h"
#include "cxfs.h"
#include "cxfsnp.h"
#include "cxfsdn.h"
#include "cmon.h"

#include "csocket.h"
#include "csys.h"
#include "cload.h"
#include "cbytes.h"
#include "csession.h"

#include "cbuffer.h"

#include "cstrkv.h"
#include "chttp.h"

#include "ctdnssv.h"
#include "cp2p.h"
#include "cdnscache.h"


//#define CMPI_DBG(x) sys_log x
#define CMPI_DBG(x) do{}while(0)

#if 0
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 pos;\
    dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "%s: ", info);\
    for(pos = 0; pos < len; pos ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif

UINT32 cmpi_encode_uint8(const UINT32 comm, const UINT8 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack(&num, 1, CMPI_UCHAR, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint8_ptr(const UINT32 comm, const UINT8 *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack(num, 1, CMPI_UCHAR, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint8_size(const UINT32 comm, const UINT8 num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_UCHAR, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint8_ptr_size(const UINT32 comm, const UINT8 *num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_UCHAR, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint8(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *num)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, num, 1, CMPI_UCHAR, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint16(const UINT32 comm, const UINT16 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&num, 1, CMPI_USHORT, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint16_ptr(const UINT32 comm, const UINT16 *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)num, 1, CMPI_USHORT, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint16_size(const UINT32 comm, const UINT16 num, UINT32 *size)
{
    //cmpi_pack_size(1, CMPI_USHORT, size,  comm);
    cmpi_pack_size(1, CMPI_USHORT, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint16_ptr_size(const UINT32 comm, const UINT16 *num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_USHORT, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint16(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT16 *num)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, 1, CMPI_USHORT, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&num, 1, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_ptr(const UINT32 comm, const UINT32 *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)num, 1, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_size(const UINT32 comm, const UINT32 num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONG, size,  comm);
    return ((UINT32)0);
}
UINT32 cmpi_encode_uint32_ptr_size(const UINT32 comm, const UINT32 *num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONG, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint32(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, 1, CMPI_ULONG, comm);
    return ((UINT32)0);
}

/*compress mode*/
UINT32 cmpi_encode_uint32_compressed_uint32_t(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    uint32_t  data;

    ASSERT(0 == (num >> 32));
    data = (uint32_t)num;
    cmpi_encode_uint32_t(comm, data, out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint32_compressed_uint32_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num)
{
    uint32_t  data;
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &data);

    (*num) = data;
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_compressed_uint32_t_size(const UINT32 comm, const UINT32 num, UINT32 *size)
{
    uint32_t  data;

    ASSERT(0 == (num >> 32));
    data = (uint32_t)num;
    cmpi_encode_uint32_t_size(comm, data, size);
    return ((UINT32)0);
}

/*compress mode*/
UINT32 cmpi_encode_uint32_compressed_uint16_t(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    uint16_t  data;

    ASSERT(0 == (num >> 16));
    data = (uint16_t)num;
    cmpi_encode_uint16(comm, data, out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint32_compressed_uint16_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num)
{
    uint16_t  data;
    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &data);

    (*num) = data;
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_compressed_uint16_t_size(const UINT32 comm, const UINT32 num, UINT32 *size)
{
    uint16_t  data;

    ASSERT(0 == (num >> 16));
    data = (uint16_t)num;
    cmpi_encode_uint16_size(comm, data, size);
    return ((UINT32)0);
}

/*compress mode*/
UINT32 cmpi_encode_uint32_compressed_uint8_t(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    uint8_t  data;

    ASSERT(0 == (num >> 8));
    data = (uint8_t)num;
    cmpi_encode_uint8(comm, data, out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint32_compressed_uint8_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num)
{
    uint8_t  data;
    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &data);

    (*num) = data;
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_compressed_uint8_t_size(const UINT32 comm, const UINT32 num, UINT32 *size)
{
    uint8_t  data;

    ASSERT(0 == (num >> 8));
    data = (uint8_t)num;
    cmpi_encode_uint8_size(comm, data, size);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_t(const UINT32 comm, const uint32_t num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&num, 1, CMPI_U32, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_t_ptr(const UINT32 comm, const uint32_t *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)num, 1, CMPI_U32, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_t_size(const UINT32 comm, const uint32_t num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_U32, size,  comm);
    return ((UINT32)0);
}
UINT32 cmpi_encode_uint32_t_ptr_size(const UINT32 comm, const uint32_t *num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_U32, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint32_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, uint32_t *num)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, 1, CMPI_U32, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint64(const UINT32 comm, const uint64_t num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&num, 1, CMPI_ULONGLONG, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint64_ptr(const UINT32 comm, const uint64_t *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)num, 1, CMPI_ULONGLONG, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint64_size(const UINT32 comm, const uint64_t num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONGLONG, size,  comm);
    return ((UINT32)0);
}
UINT32 cmpi_encode_uint64_ptr_size(const UINT32 comm, const uint64_t *num, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONGLONG, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint64(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, uint64_t *num)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, 1, CMPI_ULONGLONG, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint8_array(const UINT32 comm, const UINT8 *num, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&len, 1, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    cmpi_pack(num, len, CMPI_UCHAR, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint8_array_size(const UINT32 comm, const UINT8 *num, const UINT32 len, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONG, size,  comm);
    cmpi_pack_size(len, CMPI_UCHAR, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint8_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *num, UINT32 *len)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)len, 1,    CMPI_ULONG, comm);
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, *len, CMPI_UCHAR, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint16_array(const UINT32 comm, const UINT16 *num, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&len, 1, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    cmpi_pack((UINT8 *)num, len, CMPI_USHORT, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint16_array_size(const UINT32 comm, const UINT16 *num, const UINT32 len, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONG, size, comm);
    cmpi_pack_size(len, CMPI_USHORT, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint16_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT16 *num, UINT32 *len)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)len, 1,    CMPI_ULONG, comm);
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, *len, CMPI_USHORT, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_array(const UINT32 comm, const UINT32 *num, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&len, 1, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    cmpi_pack((UINT8 *)num, len, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_uint32_array_size(const UINT32 comm, const UINT32 *num, const UINT32 len, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONG, size,  comm);
    cmpi_pack_size(len, CMPI_ULONG, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_uint32_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num, UINT32 *len)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)len, 1,    CMPI_ULONG, comm);
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)num, *len, CMPI_ULONG, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_real_array(const UINT32 comm, const REAL *real, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)&len, 1,   CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    cmpi_pack((UINT8 *)real, len, CMPI_REAL, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_real_array_size(const UINT32 comm, const REAL *real, const UINT32 len, UINT32 *size)
{
    cmpi_pack_size(1,   CMPI_ULONG, size,  comm);
    cmpi_pack_size(len, CMPI_REAL, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_real_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, REAL *real, UINT32 *len)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)len, 1,     CMPI_ULONG, comm);
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)real, *len, CMPI_REAL, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_real(const UINT32 comm, const REAL *real, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)real, 1, CMPI_REAL, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_real_size(const UINT32 comm, const REAL *real, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_REAL, size, comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_real(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, REAL *real)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)real, 1, CMPI_REAL, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_macaddr(const UINT32 comm, const UINT8 *macaddr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_pack((UINT8 *)macaddr, 6, CMPI_UCHAR, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_macaddr_size(const UINT32 comm, const UINT8 *macaddr, UINT32 *size)
{
    cmpi_pack_size(6, CMPI_UCHAR, size, comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_macaddr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *macaddr)
{
    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)macaddr, 6, CMPI_UCHAR, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_mod_node(const UINT32 comm, const MOD_NODE *mod_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == mod_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mod_node: mod_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mod_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mod_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, MOD_NODE_TCID(mod_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MOD_NODE_COMM(mod_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MOD_NODE_RANK(mod_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MOD_NODE_MODI(mod_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MOD_NODE_HOPS(mod_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MOD_NODE_LOAD(mod_node), out_buff, out_buff_max_len, position);

    cmpi_encode_cload_stat(comm, MOD_NODE_CLOAD_STAT(mod_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_mod_node_size(const UINT32 comm, const MOD_NODE *mod_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, MOD_NODE_TCID(mod_node), size);
    cmpi_encode_uint32_size(comm, MOD_NODE_COMM(mod_node), size);
    cmpi_encode_uint32_size(comm, MOD_NODE_RANK(mod_node), size);
    cmpi_encode_uint32_size(comm, MOD_NODE_MODI(mod_node), size);
    cmpi_encode_uint32_size(comm, MOD_NODE_HOPS(mod_node), size);
    cmpi_encode_uint32_size(comm, MOD_NODE_LOAD(mod_node), size);

    cmpi_encode_cload_stat_size(comm, MOD_NODE_CLOAD_STAT(mod_node), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_mod_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MOD_NODE *mod_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mod_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mod_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == mod_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mod_node: mod_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_NODE_TCID(mod_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_NODE_COMM(mod_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_NODE_RANK(mod_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_NODE_MODI(mod_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_NODE_HOPS(mod_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_NODE_LOAD(mod_node)));

    cmpi_decode_cload_stat(comm, in_buff, in_buff_max_len, position, MOD_NODE_CLOAD_STAT(mod_node));

    return ((UINT32)0);
}

UINT32 cmpi_encode_mod_mgr(const UINT32 comm, const MOD_MGR *mod_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 pos;
    MOD_NODE *mod_node;

    UINT32 remote_mod_node_num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == mod_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mod_mgr: mod_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mod_mgr: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mod_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

#if 0
    UINT32 save_position = *position;/*for debug only*/
#endif
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    cmpi_encode_uint32(comm, (MOD_MGR_LDB_CHOICE(mod_mgr)), out_buff, out_buff_max_len, position);
    cmpi_encode_mod_node(comm, (MOD_MGR_LOCAL_MOD(mod_mgr)), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, (remote_mod_node_num), out_buff, out_buff_max_len, position);

    for(pos = 0; pos < remote_mod_node_num; pos ++)
    {
        mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        cmpi_encode_mod_node(comm, mod_node, out_buff, out_buff_max_len, position);
    }
#if 0
    print_cmpi_in_buff("cmpi_encode_mod_mgr: \n", out_buff + save_position, *position - save_position);
#endif
    return ((UINT32)0);
}

UINT32 cmpi_encode_mod_mgr_size(const UINT32 comm, const MOD_MGR *mod_mgr, UINT32 *size)
{
    UINT32 pos;
    MOD_NODE *mod_node;
    UINT32 remote_mod_node_num;
    CVECTOR *remote_mod_node_list;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    cmpi_encode_uint32_size(comm, (MOD_MGR_LDB_CHOICE(mod_mgr)), size);
    cmpi_encode_mod_node_size(comm, (MOD_MGR_LOCAL_MOD(mod_mgr)), size);
    cmpi_encode_uint32_size(comm, (remote_mod_node_num), size);

    remote_mod_node_list = (CVECTOR *)MOD_MGR_REMOTE_LIST(mod_mgr);
    for(pos = 0; pos < remote_mod_node_num; pos ++)
    {
        mod_node = (MOD_NODE *)cvector_get(remote_mod_node_list, pos);
        cmpi_encode_mod_node_size(comm, mod_node, size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_mod_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MOD_MGR *mod_mgr)
{
    CVECTOR *remote_mod_node_list;
    MOD_NODE *remote_mod_node;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mod_mgr: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mod_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == mod_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mod_mgr: mod_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */
#if 0
    UINT32 save_position = *position;/*for debug only*/
#endif
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MOD_MGR_LDB_CHOICE(mod_mgr)));
    cmpi_decode_mod_node(comm, in_buff, in_buff_max_len, position, MOD_MGR_LOCAL_MOD(mod_mgr));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(remote_mod_node_num));

    remote_mod_node_list = MOD_MGR_REMOTE_LIST(mod_mgr);
    cvector_init(remote_mod_node_list, remote_mod_node_num, MM_MOD_NODE, CVECTOR_LOCK_ENABLE, LOC_CMPIE_0001);
    cvector_codec_set(remote_mod_node_list, MM_MOD_NODE);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        alloc_static_mem(MM_MOD_NODE, &remote_mod_node, LOC_CMPIE_0002);
        cmpi_decode_mod_node(comm, in_buff, in_buff_max_len, position, remote_mod_node);
        cvector_push(remote_mod_node_list, remote_mod_node);
    }
#if 0
    print_cmpi_in_buff("cmpi_decode_mod_mgr: \n", in_buff + save_position, *position - save_position);
    dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_decode_mod_mgr: ==========================================================\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
#endif
    return ((UINT32)0);
}

UINT32 cmpi_encode_cstring(const UINT32 comm, const CSTRING *cstring, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
/*
    if ( NULL_PTR == cstring )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstring: cstring is null.\n");
        dbg_exit(MD_TBD, 0);
    }
*/
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstring: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstring: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    if(NULL_PTR == cstring)
    {
        cmpi_encode_uint32(comm, 0, out_buff, out_buff_max_len, position);
        return ((UINT32)0);
    }

    //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_encode_cstring: cstring: %lx, %s\n", cstring, (char *)cstring_get_str(cstring));
    //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_encode_cstring: cstring %lx, out_buff_max_len %ld, beg position %ld\n", cstring, out_buff_max_len, *position);

    cmpi_pack((UINT8 *)&(cstring->len), 1, CMPI_ULONG, out_buff, out_buff_max_len, position,  comm);
    cmpi_pack(cstring->str, cstring->len, CMPI_UCHAR, out_buff, out_buff_max_len, position,  comm);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cstring_size(const UINT32 comm, const CSTRING *cstring, UINT32 *size)
{
    cmpi_pack_size(1, CMPI_ULONG, size,  comm);
    if(NULL_PTR != cstring)
    {
        cmpi_pack_size(cstring->len, CMPI_UCHAR, size,  comm);
    }
    return ((UINT32)0);
}

UINT32 cmpi_decode_cstring(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSTRING *cstring)
{
    UINT32 len;
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstring: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstring: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cstring )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstring: cstring is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_decode_cstring: in_buff_max_len %ld, position %ld, cstring: %lx, %s\n", in_buff_max_len, *position, cstring, (char *)cstring_get_str(cstring));

    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)&len, 1,   CMPI_ULONG, comm);

    if(0 == len)
    {
        return ((UINT32)0);
    }

    if(EC_FALSE == cstring_expand_to(cstring, len + cstring->len + 1, LOC_CMPIE_0003))
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cstring: failed to expand cstring with capaciy %ld and len %ld to size %ld\n",
                        cstring->capacity, cstring->len, len + cstring->len + 1);
        return ((UINT32)(-1));
    }

    cmpi_unpack(in_buff, in_buff_max_len, position, cstring->str + cstring->len, len, CMPI_UCHAR, comm);
    cstring->len += len;
    cstring->str[ cstring->len ] = '\0';

    //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_decode_cstring: cstring: %lx, %s\n", cstring, (char *)cstring_get_str(cstring));

    return ((UINT32)0);
}

UINT32 cmpi_encode_taskc_node(const UINT32 comm, const TASKC_NODE *taskc_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == taskc_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_taskc_node: taskc_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_taskc_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_taskc_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, TASKC_NODE_TCID(taskc_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASKC_NODE_COMM(taskc_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASKC_NODE_SIZE(taskc_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_taskc_node_size(const UINT32 comm, const TASKC_NODE *taskc_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, TASKC_NODE_TCID(taskc_node), size);
    cmpi_encode_uint32_size(comm, TASKC_NODE_COMM(taskc_node), size);
    cmpi_encode_uint32_size(comm, TASKC_NODE_SIZE(taskc_node), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_taskc_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASKC_NODE *taskc_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_taskc_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_taskc_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == taskc_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_taskc_node: taskc_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASKC_NODE_TCID(taskc_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASKC_NODE_COMM(taskc_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASKC_NODE_SIZE(taskc_node)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_taskc_mgr(const UINT32 comm, const TASKC_MGR *taskc_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    CLIST *taskc_node_list;
    CLIST_DATA *clist_data;

    UINT32 taskc_node_idx;
    UINT32 taskc_node_num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == taskc_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_taskc_mgr: taskc_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_taskc_mgr: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_taskc_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(taskc_mgr);
    taskc_node_num = clist_size(taskc_node_list);

    cmpi_encode_uint32(comm, taskc_node_num, out_buff, out_buff_max_len, position);

    taskc_node_idx = 0;
    CLIST_LOOP_NEXT(taskc_node_list, clist_data)
    {
        TASKC_NODE *taskc_node;
        taskc_node = (TASKC_NODE *)CLIST_DATA_DATA(clist_data);
        cmpi_encode_taskc_node(comm, taskc_node, out_buff, out_buff_max_len, position);
        taskc_node_idx ++;
    }

    /*validity checking*/
    if(taskc_node_idx != taskc_node_num)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_taskc_mgr: encoded taskc node num = %ld, but clist size = %ld\n", taskc_node_idx, taskc_node_num);
        dbg_exit(MD_TBD, 0);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_taskc_mgr_size(const UINT32 comm, const TASKC_MGR *taskc_mgr, UINT32 *size)
{
    CLIST *taskc_node_list;
    CLIST_DATA *clist_data;

    UINT32 taskc_node_idx;
    UINT32 taskc_node_num;

    taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(taskc_mgr);
    taskc_node_num = clist_size(taskc_node_list);

    cmpi_encode_uint32_size(comm, taskc_node_num, size);

    taskc_node_idx = 0;
    CLIST_LOOP_NEXT(taskc_node_list, clist_data)
    {
        TASKC_NODE *taskc_node;
        taskc_node = (TASKC_NODE *)CLIST_DATA_DATA(clist_data);
        cmpi_encode_taskc_node_size(comm, taskc_node, size);
        taskc_node_idx ++;
    }

    /*validity checking*/
    if(taskc_node_idx != taskc_node_num)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_taskc_mgr_size: encoded taskc node num = %ld, but clist size = %ld\n", taskc_node_idx, taskc_node_num);
        dbg_exit(MD_TBD, 0);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_taskc_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASKC_MGR *taskc_mgr)
{
    CLIST *taskc_node_list;
    TASKC_NODE *taskc_node;

    UINT32 taskc_node_num;
    UINT32 taskc_node_idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_taskc_mgr: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_taskc_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == taskc_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_taskc_mgr: taskc_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    taskc_node_list = TASKC_MGR_NODE_LIST(taskc_mgr);

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(taskc_node_num));

    //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_decode_taskc_mgr: before decode, taskc_node_list is:\n");
    //clist_print(LOGSTDOUT, taskc_node_list, (CLIST_DATA_DATA_PRINT)tst_taskc_node_print);

    for(taskc_node_idx = 0; taskc_node_idx < taskc_node_num; taskc_node_idx ++)
    {
        taskc_node = taskc_node_new();
        if(NULL_PTR == taskc_node)
        {
            dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_taskc_mgr: failed to alloc TASKC_NODE when idx = %ld\n", taskc_node_idx);
            return ((UINT32)(-1));
        }
        cmpi_decode_taskc_node(comm, in_buff, in_buff_max_len, position, taskc_node);

        clist_push_back(taskc_node_list, (void *)taskc_node);
        //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_decode_taskc_mgr: new taskc_node %lx\n", taskc_node);

        //dbg_log(SEC_0035_CMPIE, 5)(LOGSTDOUT, "cmpi_decode_taskc_mgr: after decode # %ld, taskc_node_list is:\n", taskc_node_idx);
        //clist_print(LOGSTDOUT, taskc_node_list, (CLIST_DATA_DATA_PRINT)tst_taskc_node_print);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_log(const UINT32 comm, const LOG *log, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == log )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_log: log is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_log: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_log: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, LOG_DEVICE_TYPE(log), out_buff, out_buff_max_len, position);
    if(LOG_FILE_DEVICE == LOG_DEVICE_TYPE(log))
    {
        UINT32 fd;

        if(LOGSTDOUT == log || stdout == LOG_FILE_FP(log))
        {
            fd = (UINT32)DEFAULT_STDOUT_LOG_INDEX;
        }
        else if(LOGSTDIN == log || stdin == LOG_FILE_FP(log))
        {
            fd = (UINT32)DEFAULT_STDIN_LOG_INDEX;
        }
        else if(LOGSTDERR == log || stderr == LOG_FILE_FP(log))
        {
            fd = (UINT32)DEFAULT_STDERR_LOG_INDEX;
        }
        else
        {
            fd = (UINT32)DEFAULT_STDNULL_LOG_INDEX;
        }
        cmpi_encode_uint32(comm, fd, out_buff, out_buff_max_len, position);
    }
    if(LOG_CSTR_DEVICE == LOG_DEVICE_TYPE(log))
    {
        cmpi_encode_cstring(comm, LOG_CSTR(log), out_buff, out_buff_max_len, position);
    }

    cmpi_encode_uint32(comm, LOG_SWITCH_OFF_ENABLE(log), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_log_size(const UINT32 comm, const LOG *log, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, LOG_DEVICE_TYPE(log), size);
    if(LOG_FILE_DEVICE == LOG_DEVICE_TYPE(log))
    {
        UINT32 fd;
        fd = DEFAULT_STDNULL_LOG_INDEX;/*any value*/
        cmpi_encode_uint32_size(comm, fd, size);
    }
    if(LOG_CSTR_DEVICE == LOG_DEVICE_TYPE(log))
    {
        cmpi_encode_cstring_size(comm, LOG_CSTR(log), size);
    }

    cmpi_encode_uint32_size(comm, LOG_SWITCH_OFF_ENABLE(log), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_log(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, LOG *log)
{
    UINT32 type;
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_log: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_log: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == log )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_log: log is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &type);
    LOG_DEVICE_TYPE(log) = type;

    if(LOG_FILE_DEVICE == LOG_DEVICE_TYPE(log))
    {
        UINT32 fd;
        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &fd);

        log_file_init(log, NULL_PTR, NULL_PTR,
                        CMPI_ERROR_TCID, CMPI_ERROR_RANK,
                        LOGD_FILE_RECORD_LIMIT_DISABLED, (UINT32)SWITCH_OFF,
                        LOGD_SWITCH_OFF_DISABLE, LOGD_PID_INFO_ENABLE);

        if(DEFAULT_STDOUT_LOG_INDEX == fd)
        {
            LOG_FILE_FP(log) = stdout;
            LOG_REDIRECT(log) = LOGSTDOUT;
        }
        else if(DEFAULT_STDIN_LOG_INDEX == fd)
        {
            LOG_FILE_FP(log) = stdin;
            LOG_REDIRECT(log) = LOGSTDIN;
        }
        else if(DEFAULT_STDERR_LOG_INDEX == fd)
        {
            LOG_FILE_FP(log) = stderr;
            LOG_REDIRECT(log) = LOGSTDERR;
        }
        else
        {
            LOG_FILE_FP(log) = NULL_PTR;
        }
    }

    if(LOG_CSTR_DEVICE == LOG_DEVICE_TYPE(log))
    {
        LOG_REDIRECT(log)  = NULL_PTR;

        if(NULL_PTR == LOG_CSTR(log))
        {
            LOG_CSTR(log) = cstring_new(NULL_PTR, LOC_CMPIE_0004);
        }
        else
        {
           cstring_reset(LOG_CSTR(log));
        }
        cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, LOG_CSTR(log));
    }

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(LOG_SWITCH_OFF_ENABLE(log)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_kbuff(const UINT32 comm, const KBUFF *kbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == kbuff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_kbuff: kbuff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_kbuff: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_kbuff: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */
/*
    if(NULL_PTR == KBUFF_CACHE(kbuff))
    {
        UINT32 len;

        len = 0;
        cmpi_encode_uint32(comm, len, out_buff, out_buff_max_len, position);

        return ((UINT32)0);
    }
*/
    cmpi_encode_uint32(comm, KBUFF_CUR_LEN(kbuff), out_buff, out_buff_max_len, position);
    for(idx = 0; idx < KBUFF_CUR_LEN(kbuff); idx ++)
    {
        cmpi_encode_uint8(comm, KBUFF_CACHE_CHAR(kbuff, idx), out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_kbuff_size(const UINT32 comm, const KBUFF *kbuff, UINT32 *size)
{
    UINT32 idx;
/*
    if(NULL_PTR == KBUFF_CACHE(kbuff))
    {
        UINT32 len;

        len = 0;
        cmpi_encode_uint32_size(comm, len, size);

        return ((UINT32)0);
    }
*/
    cmpi_encode_uint32_size(comm, KBUFF_CUR_LEN(kbuff), size);
    for(idx = 0; idx < KBUFF_CUR_LEN(kbuff); idx ++)
    {
        cmpi_encode_uint8_size(comm, KBUFF_CACHE_CHAR(kbuff, idx), size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_kbuff(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, KBUFF *kbuff)
{
    UINT32 len;
    UINT32 idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_kbuff: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_kbuff: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == kbuff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_kbuff: kbuff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &len);
    if(0 == len)
    {
        /*nothing to do*/
        return ((UINT32)0);
    }

    if(NULL_PTR == KBUFF_CACHE(kbuff))
    {
#if 0
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_kbuff: to decode len %ld but kbuff %p cache is null\n",
                           len, kbuff);
        return ((UINT32)-1);
#endif
        kbuff_init(kbuff,len);
    }

    if(len + KBUFF_CUR_LEN(kbuff) > KBUFF_MAX_LEN(kbuff))
    {
#if 1
       dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_kbuff: len %ld overflow kbuff %p with cur len %ld and max len %ld\n",
                           len, kbuff, KBUFF_CUR_LEN(kbuff), KBUFF_MAX_LEN(kbuff));
       return ((UINT32)-1);
#endif

    }

    for(idx = 0; idx < len; idx ++)
    {
        cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, KBUFF_CACHE(kbuff) + KBUFF_CUR_LEN(kbuff) + idx);
    }

    KBUFF_CUR_LEN(kbuff) += len;

    //dbg_log(SEC_0035_CMPIE, 3)(LOGSTDOUT, "info:cmpi_decode_kbuff: encoded len = %ld and kbuff %p, cur_len = %ld, max_len = %ld\n", len, kbuff, KBUFF_CUR_LEN(kbuff), KBUFF_MAX_LEN(kbuff));

    return ((UINT32)0);
}

UINT32 cmpi_encode_cvector(const UINT32 comm, const CVECTOR *cvector, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 num;
    UINT32 type;

    UINT32 pos;
    CVECTOR_DATA_ENCODER data_encoder;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cvector )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cvector: cvector is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cvector: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cvector: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    type = cvector_type(cvector);
    num = cvector_size(cvector);

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_cvector: cvector %p, type = %ld, num = %ld, position = %ld\n",
                        cvector, type, num, *position));

    cmpi_encode_uint32(comm, type, out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    if(0 == num)
    {
        return ((UINT32)0);
    }

    data_encoder = (CVECTOR_DATA_ENCODER)cvector_codec_get(cvector, CVECTOR_CODEC_ENCODER);
    if(NULL_PTR == data_encoder)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_cvector: cvector data encoder is null\n");
        return ((UINT32)-1);
    }
#if 0
    if(MM_UINT32 == type)
    {
        for(pos = 0; pos < num; pos ++)
        {
            //void * data;
            //data = (void *)cvector_get_addr(cvector, pos);
            UINT32 data;
            data = (UINT32)cvector_get(cvector, pos);
            data_encoder(comm, data, out_buff, out_buff_max_len, position);
        }
    }
    else/*non UINT32*/
    {
        for(pos = 0; pos < num; pos ++)
        {
            void * data;
            data = cvector_get(cvector, pos);

            data_encoder(comm, data, out_buff, out_buff_max_len, position);
        }
    }
#endif

#if 1
    for(pos = 0; pos < num; pos ++)
    {
        void * data;
        data = cvector_get(cvector, pos);

        data_encoder(comm, data, out_buff, out_buff_max_len, position);
    }
#endif
    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_cvector: cvector %p, type = %ld, num = %ld ==> position = %ld\n",
                        cvector, cvector_type(cvector), cvector_size(cvector), *position));

    return ((UINT32)0);
}

UINT32 cmpi_encode_cvector_size(const UINT32 comm, const CVECTOR *cvector, UINT32 *size)
{
    UINT32 num;
    UINT32 type;

    UINT32 pos;
    CVECTOR_DATA_ENCODER_SIZE data_encoder_size;

    type = cvector_type(cvector);
    num = cvector_size(cvector);

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_cvector_size: cvector %p: type = %ld, num = %ld, size = %ld\n", cvector, type, num, *size));

    if(MM_END == type)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_cvector_size: cvector %p: invalid type = %ld, num = %ld\n", cvector, type, num);
    }

    cmpi_encode_uint32_size(comm, type, size);
    cmpi_encode_uint32_size(comm, num, size);

    if(0 == num)
    {
        return ((UINT32)0);
    }

    data_encoder_size = (CVECTOR_DATA_ENCODER_SIZE)cvector_codec_get(cvector, CVECTOR_CODEC_ENCODER_SIZE);
    if(NULL_PTR == data_encoder_size)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_cvector_size: cvector %p: type = %ld, num = %ld, data encoder_size is null\n",
                            cvector, type, num);
        return ((UINT32)-1);
    }

     //dbg_log(SEC_0035_CMPIE, 0)(LOGCONSOLE, "[DEBUG] cmpi_encode_cvector_size: cvector %p, mm type %ld\n", cvector, cvector->data_mm_type);

    if(MM_UINT32 == type)
    {
        for(pos = 0; pos < num; pos ++)
        {
            void * data;
            data = (void *)cvector_get_addr(cvector, pos);
            data_encoder_size(comm, data, size);
        }
    }
    else/*non UINT32*/
    {
        for(pos = 0; pos < num; pos ++)
        {
            void * data;
            data = cvector_get(cvector, pos);
            data_encoder_size(comm, data, size);
        }
    }

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_cvector_size: cvector %p: type = %ld, num = %ld, ==> size %ld\n",
                            cvector, cvector_type(cvector), cvector_size(cvector), *size));

    return ((UINT32)0);
}

UINT32 cmpi_decode_cvector(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CVECTOR *cvector)
{
    UINT32 num;
    UINT32 type;

    UINT32 pos;
    CVECTOR_DATA_DECODER data_decoder;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cvector: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cvector: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cvector )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cvector: cvector is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(type));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(num));

    dbg_log(SEC_0035_CMPIE, 3)(LOGSTDNULL, "info:cmpi_decode_cvector: enter: cvector %p, type = %ld, num = %ld, size = %ld\n", cvector, type, num, cvector->size);

    if(type != cvector->data_mm_type)
    {
        dbg_log(SEC_0035_CMPIE, 3)(LOGSTDNULL, "info:cmpi_decode_cvector: cvector %p, data type %ld ==> %ld\n", cvector, cvector->data_mm_type, type);
        cvector_codec_set(cvector, type);
    }
    dbg_log(SEC_0035_CMPIE, 3)(LOGSTDNULL, "info:cmpi_decode_cvector: [0] cvector %p, data type %ld \n", cvector, cvector->data_mm_type);

    if(0 == num)
    {
        return ((UINT32)0);
    }
#if 0
    if(0 < cvector_size(cvector))
    {
        if(MM_UINT32 == type)
        {
            cvector_clean(cvector, NULL_PTR, LOC_CMPIE_0005);
        }
        else
        {
            UINT32 size;
            CVECTOR_DATA_FREE data_free;

            size = cvector_size(cvector);
            data_free = (CVECTOR_DATA_FREE)cvector_codec_get(cvector, CVECTOR_CODEC_FREE);
            for(pos = 0; pos < size; pos ++)
            {
                void *data;
                data = cvector_get(cvector, pos);
                data_free(CMPI_ANY_MODI, data);
            }
            cvector_clean(cvector, NULL_PTR, LOC_CMPIE_0006);
        }
    }
#endif
    data_decoder = (CVECTOR_DATA_DECODER)cvector_codec_get(cvector, CVECTOR_CODEC_DECODER);
    if(NULL_PTR == data_decoder)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cvector: cvector %p data decoder is null\n", cvector);
        return ((UINT32)-1);
    }

    if(MM_UINT32 == type)
    {
        UINT32 size;

        size = cvector_size(cvector);

        /*re-use the old item to accept the decoded result*/
        for(pos = 0; pos < size && pos < num; pos ++)
        {
            void * data;
            data = (void *)cvector_get_addr(cvector, pos);
            if(NULL_PTR == data)
            {
                data = (void *)cvector_get_addr(cvector, pos);
                //dbg_log(SEC_0035_CMPIE, 3)(LOGSTDOUT, "info:cmpi_decode_cvector: [2] cvector %p, size %ld, capacity %ld\n", cvector, cvector->size, cvector->capacity);
            }
            data_decoder(comm, in_buff, in_buff_max_len, position, data);
        }

        /*alloc new item to accept the decoded result, and push the new item*/
        for(; pos < num; pos ++)
        {
            void * data;
            cvector_push(cvector, (void *)0);/*add new one*/
            data = (void *)cvector_get_addr(cvector, pos);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cvector: cvector %p, size %ld, capacity %ld, pos = %ld is null\n",
                                    cvector, cvector->size, cvector->capacity, pos);
                return ((UINT32)-1);
            }
            data_decoder(comm, in_buff, in_buff_max_len, position, data);
        }
    }
    else/*non UINT32*/
    {
        UINT32 size;

        CVECTOR_DATA_INIT    data_init;

        data_init = (CVECTOR_DATA_INIT)cvector_codec_get(cvector, CVECTOR_CODEC_INIT);/*data_init may be null pointer*/
        if(NULL_PTR == data_init)
        {
            dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cvector: cvector %p data init is null\n", cvector);
            return ((UINT32)-1);
        }

        size = cvector_size(cvector);

        /*re-use the old item to accept the decoded result*/
        for(pos = 0; pos < size && pos < num; pos ++)
        {
            void * data;
            data = cvector_get(cvector, pos);
            if(NULL_PTR == data)
            {
                alloc_static_mem(type, &data, LOC_CMPIE_0007);
                data_init(data);
                cvector_set(cvector, pos, (void *)data);/*add new one*/
                //dbg_log(SEC_0035_CMPIE, 3)(LOGSTDOUT, "info:cmpi_decode_cvector: [3] cvector %p, size %ld, capacity %ld\n", cvector, cvector->size, cvector->capacity);
            }
            data_decoder(comm, in_buff, in_buff_max_len, position, data);
        }

        /*alloc new item to accept the decoded result, and push the new item*/
        for(; pos < num; pos ++)
        {
            void * data;

            alloc_static_mem(type, &data, LOC_CMPIE_0008);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cvector: [3] cvector %p, size %ld, capacity %ld, pos = %ld failed to alloc\n",
                                    cvector, cvector->size, cvector->capacity, pos);
            }
            data_init(data);
            data_decoder(comm, in_buff, in_buff_max_len, position, data);
            cvector_push(cvector, (void *)data);/*add new one*/
        }
    }
    CMPI_DBG((LOGSTDOUT, "info:cmpi_decode_cvector: leave: cvector %p, type = %ld, num = %ld, size = %ld\n", cvector, type, num, cvector->size));
    return ((UINT32)0);
}

UINT32 cmpi_encode_csocket_cnode(const UINT32 comm, const CSOCKET_CNODE *csocket_cnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 sockfd;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == csocket_cnode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csocket_cnode: csocket_cnode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csocket_cnode: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csocket_cnode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    sockfd = INT32_TO_UINT32(CSOCKET_CNODE_SOCKFD(csocket_cnode));

    cmpi_encode_uint32(comm, CSOCKET_CNODE_IPADDR(csocket_cnode) , out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSOCKET_CNODE_SRVPORT(csocket_cnode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSOCKET_CNODE_TCID(csocket_cnode)   , out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSOCKET_CNODE_COMM(csocket_cnode)   , out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSOCKET_CNODE_SIZE(csocket_cnode)   , out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, sockfd                              , out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csocket_cnode_size(const UINT32 comm, const CSOCKET_CNODE *csocket_cnode, UINT32 *size)
{
    UINT32 sockfd;

    sockfd = INT32_TO_UINT32(CSOCKET_CNODE_SOCKFD(csocket_cnode));

    cmpi_encode_uint32_size(comm, CSOCKET_CNODE_IPADDR(csocket_cnode) , size);
    cmpi_encode_uint32_size(comm, CSOCKET_CNODE_SRVPORT(csocket_cnode), size);
    cmpi_encode_uint32_size(comm, CSOCKET_CNODE_TCID(csocket_cnode)   , size);
    cmpi_encode_uint32_size(comm, CSOCKET_CNODE_COMM(csocket_cnode)   , size);
    cmpi_encode_uint32_size(comm, CSOCKET_CNODE_SIZE(csocket_cnode)   , size);
    cmpi_encode_uint32_size(comm, sockfd                              , size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_csocket_cnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSOCKET_CNODE *csocket_cnode)
{
    UINT32 sockfd;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csocket_cnode: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csocket_cnode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == csocket_cnode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csocket_cnode: csocket_cnode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSOCKET_CNODE_IPADDR(csocket_cnode)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSOCKET_CNODE_SRVPORT(csocket_cnode)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSOCKET_CNODE_TCID(csocket_cnode))   );
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSOCKET_CNODE_COMM(csocket_cnode))   );
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSOCKET_CNODE_SIZE(csocket_cnode))   );
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(sockfd)                               );

    CSOCKET_CNODE_SOCKFD(csocket_cnode) = (int)UINT32_TO_INT32(sockfd);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csys_cpu_stat(const UINT32 comm, const CSYS_CPU_STAT *csys_cpu_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == csys_cpu_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_cpu_stat: csys_cpu_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_cpu_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_cpu_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CSYS_CPU_STAT_CSTR(csys_cpu_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_CPU_STAT_USER(csys_cpu_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_CPU_STAT_NICE(csys_cpu_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_CPU_STAT_SYS(csys_cpu_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_CPU_STAT_IDLE(csys_cpu_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_CPU_STAT_TOTAL(csys_cpu_stat), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csys_cpu_stat_size(const UINT32 comm, const CSYS_CPU_STAT *csys_cpu_stat, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CSYS_CPU_STAT_CSTR(csys_cpu_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_CPU_STAT_USER(csys_cpu_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_CPU_STAT_NICE(csys_cpu_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_CPU_STAT_SYS(csys_cpu_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_CPU_STAT_IDLE(csys_cpu_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_CPU_STAT_TOTAL(csys_cpu_stat), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_csys_cpu_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSYS_CPU_STAT *csys_cpu_stat)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_cpu_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_cpu_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == csys_cpu_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_cpu_stat: csys_cpu_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSYS_CPU_STAT_CSTR(csys_cpu_stat));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_CPU_STAT_USER(csys_cpu_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_CPU_STAT_NICE(csys_cpu_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_CPU_STAT_SYS(csys_cpu_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_CPU_STAT_IDLE(csys_cpu_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_CPU_STAT_TOTAL(csys_cpu_stat)));

    return ((UINT32)0);
}


UINT32 cmpi_encode_mm_man_occupy_node(const UINT32 comm, const MM_MAN_OCCUPY_NODE *mm_man_occupy_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == mm_man_occupy_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mm_man_occupy_node: mm_man_occupy_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mm_man_occupy_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mm_man_occupy_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node) , out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node) , out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node) , out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_mm_man_occupy_node_size(const UINT32 comm, const MM_MAN_OCCUPY_NODE *mm_man_occupy_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node), size);
    cmpi_encode_uint32_size(comm, MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node) , size);
    cmpi_encode_uint32_size(comm, MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node) , size);
    cmpi_encode_uint32_size(comm, MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node) , size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_mm_man_occupy_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MM_MAN_OCCUPY_NODE *mm_man_occupy_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mm_man_occupy_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mm_man_occupy_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == mm_man_occupy_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mm_man_occupy_node: mm_man_occupy_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MM_MAN_OCCUPY_NODE_TYPE(mm_man_occupy_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MM_MAN_OCCUPY_NODE_SUM(mm_man_occupy_node) ));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MM_MAN_OCCUPY_NODE_MAX(mm_man_occupy_node) ));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MM_MAN_OCCUPY_NODE_CUR(mm_man_occupy_node) ));

    return ((UINT32)0);
}

UINT32 cmpi_encode_mm_man_load_node(const UINT32 comm, const MM_MAN_LOAD_NODE *mm_man_load_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == mm_man_load_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mm_man_load_node: mm_man_load_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mm_man_load_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_mm_man_load_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, MM_MAN_LOAD_NODE_TYPE(mm_man_load_node), out_buff, out_buff_max_len, position);
    cmpi_encode_real(comm, &(MM_MAN_LOAD_NODE_MAX(mm_man_load_node)), out_buff, out_buff_max_len, position);
    cmpi_encode_real(comm, &(MM_MAN_LOAD_NODE_CUR(mm_man_load_node)), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_mm_man_load_node_size(const UINT32 comm, const MM_MAN_LOAD_NODE *mm_man_load_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, MM_MAN_LOAD_NODE_TYPE(mm_man_load_node), size);
    cmpi_encode_real_size(comm, &(MM_MAN_LOAD_NODE_MAX(mm_man_load_node)), size);
    cmpi_encode_real_size(comm, &(MM_MAN_LOAD_NODE_CUR(mm_man_load_node)), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_mm_man_load_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MM_MAN_LOAD_NODE *mm_man_load_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mm_man_load_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mm_man_load_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == mm_man_load_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_mm_man_load_node: mm_man_load_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(MM_MAN_LOAD_NODE_TYPE(mm_man_load_node)));
    cmpi_decode_real(comm, in_buff, in_buff_max_len, position, &(MM_MAN_LOAD_NODE_MAX(mm_man_load_node)));
    cmpi_decode_real(comm, in_buff, in_buff_max_len, position, &(MM_MAN_LOAD_NODE_CUR(mm_man_load_node)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_cproc_module_stat(const UINT32 comm, const CPROC_MODULE_STAT *cproc_module_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cproc_module_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cproc_module_stat: cproc_module_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cproc_module_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cproc_module_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, CPROC_MODULE_TYPE(cproc_module_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CPROC_MODULE_NUM(cproc_module_stat), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cproc_module_stat_size(const UINT32 comm, const CPROC_MODULE_STAT *cproc_module_stat, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, CPROC_MODULE_TYPE(cproc_module_stat), size);
    cmpi_encode_uint32_size(comm, CPROC_MODULE_NUM(cproc_module_stat), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_cproc_module_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CPROC_MODULE_STAT *cproc_module_stat)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cproc_module_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cproc_module_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cproc_module_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cproc_module_stat: cproc_module_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CPROC_MODULE_TYPE(cproc_module_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CPROC_MODULE_NUM(cproc_module_stat)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_crank_thread_stat(const UINT32 comm, const CRANK_THREAD_STAT *crank_thread_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crank_thread_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crank_thread_stat: crank_thread_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crank_thread_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crank_thread_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, CRANK_THREAD_MAX_NUM(crank_thread_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CRANK_THREAD_BUSY_NUM(crank_thread_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CRANK_THREAD_IDLE_NUM(crank_thread_stat), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_crank_thread_stat_size(const UINT32 comm, const CRANK_THREAD_STAT *crank_thread_stat, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, CRANK_THREAD_MAX_NUM(crank_thread_stat), size);
    cmpi_encode_uint32_size(comm, CRANK_THREAD_BUSY_NUM(crank_thread_stat), size);
    cmpi_encode_uint32_size(comm, CRANK_THREAD_IDLE_NUM(crank_thread_stat), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_crank_thread_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRANK_THREAD_STAT *crank_thread_stat)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crank_thread_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crank_thread_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crank_thread_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crank_thread_stat: crank_thread_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CRANK_THREAD_MAX_NUM(crank_thread_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CRANK_THREAD_BUSY_NUM(crank_thread_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CRANK_THREAD_IDLE_NUM(crank_thread_stat)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_csys_eth_stat(const UINT32 comm, const CSYS_ETH_STAT *csys_eth_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == csys_eth_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_eth_stat: csys_eth_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_eth_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_eth_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CSYS_ETH_NAME(csys_eth_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_ETH_SPEEDMBS(csys_eth_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_ETH_RXMOCT(csys_eth_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_ETH_TXMOCT(csys_eth_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_ETH_RXTHROUGHPUT(csys_eth_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_ETH_TXTHROUGHPUT(csys_eth_stat), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csys_eth_stat_size(const UINT32 comm, const CSYS_ETH_STAT *csys_eth_stat, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CSYS_ETH_NAME(csys_eth_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_ETH_SPEEDMBS(csys_eth_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_ETH_RXMOCT(csys_eth_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_ETH_TXMOCT(csys_eth_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_ETH_RXTHROUGHPUT(csys_eth_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_ETH_TXTHROUGHPUT(csys_eth_stat), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_csys_eth_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSYS_ETH_STAT *csys_eth_stat)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_eth_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_eth_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == csys_eth_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_eth_stat: csys_eth_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSYS_ETH_NAME(csys_eth_stat));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_ETH_SPEEDMBS(csys_eth_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_ETH_RXMOCT(csys_eth_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_ETH_TXMOCT(csys_eth_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_ETH_RXTHROUGHPUT(csys_eth_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_ETH_TXTHROUGHPUT(csys_eth_stat)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_csys_dsk_stat(const UINT32 comm, const CSYS_DSK_STAT *csys_dsk_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == csys_dsk_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_dsk_stat: csys_dsk_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_dsk_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csys_dsk_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CSYS_DSK_NAME(csys_dsk_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_DSK_SIZE(csys_dsk_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_DSK_USED(csys_dsk_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSYS_DSK_AVAL(csys_dsk_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_real(comm, &(CSYS_DSK_LOAD(csys_dsk_stat)), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csys_dsk_stat_size(const UINT32 comm, const CSYS_DSK_STAT *csys_dsk_stat, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CSYS_DSK_NAME(csys_dsk_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_DSK_SIZE(csys_dsk_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_DSK_USED(csys_dsk_stat), size);
    cmpi_encode_uint32_size(comm, CSYS_DSK_AVAL(csys_dsk_stat), size);
    cmpi_encode_real_size(comm, &(CSYS_DSK_LOAD(csys_dsk_stat)), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_csys_dsk_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSYS_DSK_STAT *csys_dsk_stat)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_dsk_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_dsk_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == csys_dsk_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csys_dsk_stat: csys_dsk_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSYS_DSK_NAME(csys_dsk_stat));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_DSK_SIZE(csys_dsk_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_DSK_USED(csys_dsk_stat)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CSYS_DSK_AVAL(csys_dsk_stat)));
    cmpi_decode_real(comm, in_buff, in_buff_max_len, position, &(CSYS_DSK_LOAD(csys_dsk_stat)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_task_time_fmt(const UINT32 comm, const TASK_TIME_FMT *task_time_fmt, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == task_time_fmt )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_task_time_fmt: task_time_fmt is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_task_time_fmt: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_task_time_fmt: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, TASK_TIME_FMT_YEAR(task_time_fmt), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_TIME_FMT_MONTH(task_time_fmt), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_TIME_FMT_MDAY(task_time_fmt), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_TIME_FMT_HOUR(task_time_fmt), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_TIME_FMT_MIN(task_time_fmt), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_TIME_FMT_SEC(task_time_fmt), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_task_time_fmt_size(const UINT32 comm, const TASK_TIME_FMT *task_time_fmt, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, TASK_TIME_FMT_YEAR(task_time_fmt), size);
    cmpi_encode_uint32_size(comm, TASK_TIME_FMT_MONTH(task_time_fmt), size);
    cmpi_encode_uint32_size(comm, TASK_TIME_FMT_MDAY(task_time_fmt), size);
    cmpi_encode_uint32_size(comm, TASK_TIME_FMT_HOUR(task_time_fmt), size);
    cmpi_encode_uint32_size(comm, TASK_TIME_FMT_MIN(task_time_fmt), size);
    cmpi_encode_uint32_size(comm, TASK_TIME_FMT_SEC(task_time_fmt), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_task_time_fmt(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASK_TIME_FMT *task_time_fmt)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_task_time_fmt: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_task_time_fmt: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == task_time_fmt )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_task_time_fmt: task_time_fmt is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_TIME_FMT_YEAR(task_time_fmt)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_TIME_FMT_MONTH(task_time_fmt)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_TIME_FMT_MDAY(task_time_fmt)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_TIME_FMT_HOUR(task_time_fmt)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_TIME_FMT_MIN(task_time_fmt)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_TIME_FMT_SEC(task_time_fmt)));

    return ((UINT32)0);
}


UINT32 cmpi_encode_task_report_node(const UINT32 comm, const TASK_REPORT_NODE *task_report_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == task_report_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_task_report_node: task_report_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_task_report_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_task_report_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_task_time_fmt(comm, TASK_REPORT_NODE_START_TIME(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_task_time_fmt(comm, TASK_REPORT_NODE_END_TIME(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_TCID(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_RANK(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_SEQNO(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_WAIT_FLAG(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_task_report_node_size(const UINT32 comm, const TASK_REPORT_NODE *task_report_node, UINT32 *size)
{
    cmpi_encode_task_time_fmt_size(comm, TASK_REPORT_NODE_START_TIME(task_report_node), size);
    cmpi_encode_task_time_fmt_size(comm, TASK_REPORT_NODE_END_TIME(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_TCID(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_RANK(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_SEQNO(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_WAIT_FLAG(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node), size);
    cmpi_encode_uint32_size(comm, TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_task_report_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASK_REPORT_NODE *task_report_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_task_report_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_task_report_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == task_report_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_task_report_node: task_report_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_task_time_fmt(comm, in_buff, in_buff_max_len, position, TASK_REPORT_NODE_START_TIME(task_report_node));
    cmpi_decode_task_time_fmt(comm, in_buff, in_buff_max_len, position, TASK_REPORT_NODE_END_TIME(task_report_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_TCID(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_RANK(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_SEQNO(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_TIME_TO_LIVE(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_WAIT_FLAG(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_NEED_RSP_FLAG(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_NEED_RESCHEDULE_FLAG(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_TOTAL_REQ_NUM(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_SENT_REQ_NUM(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_DISCARD_REQ_NUM(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_TIMEOUT_REQ_NUM(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_NEED_RSP_NUM(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_SUCC_RSP_NUM(task_report_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(TASK_REPORT_NODE_FAIL_RSP_NUM(task_report_node)));
    return ((UINT32)0);
}

UINT32 cmpi_encode_cload_stat(const UINT32 comm, const CLOAD_STAT *cload_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cload_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_stat: cload_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint16(comm, CLOAD_STAT_QUE_LOAD(cload_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint16(comm, CLOAD_STAT_OBJ_LOAD(cload_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint8(comm, CLOAD_STAT_CPU_LOAD(cload_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint8(comm, CLOAD_STAT_MEM_LOAD(cload_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint8(comm, CLOAD_STAT_DSK_LOAD(cload_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint8(comm, CLOAD_STAT_NET_LOAD(cload_stat), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cload_stat_size(const UINT32 comm, const CLOAD_STAT *cload_stat, UINT32 *size)
{
    cmpi_encode_uint16_size(comm, CLOAD_STAT_QUE_LOAD(cload_stat), size);
    cmpi_encode_uint16_size(comm, CLOAD_STAT_OBJ_LOAD(cload_stat), size);
    cmpi_encode_uint8_size(comm, CLOAD_STAT_CPU_LOAD(cload_stat), size);
    cmpi_encode_uint8_size(comm, CLOAD_STAT_MEM_LOAD(cload_stat), size);
    cmpi_encode_uint8_size(comm, CLOAD_STAT_DSK_LOAD(cload_stat), size);
    cmpi_encode_uint8_size(comm, CLOAD_STAT_NET_LOAD(cload_stat), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cload_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLOAD_STAT *cload_stat)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cload_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_stat: cload_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CLOAD_STAT_QUE_LOAD(cload_stat)));
    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CLOAD_STAT_OBJ_LOAD(cload_stat)));
    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &(CLOAD_STAT_CPU_LOAD(cload_stat)));
    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &(CLOAD_STAT_MEM_LOAD(cload_stat)));
    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &(CLOAD_STAT_DSK_LOAD(cload_stat)));
    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &(CLOAD_STAT_NET_LOAD(cload_stat)));

    return ((UINT32)0);
}


UINT32 cmpi_encode_cload_node(const UINT32 comm, const CLOAD_NODE *cload_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cload_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_node: cload_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, CLOAD_NODE_TCID(cload_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CLOAD_NODE_COMM(cload_node), out_buff, out_buff_max_len, position);
    cmpi_encode_cvector(comm, CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cload_node_size(const UINT32 comm, const CLOAD_NODE *cload_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, CLOAD_NODE_TCID(cload_node), size);
    cmpi_encode_uint32_size(comm, CLOAD_NODE_COMM(cload_node), size);
    cmpi_encode_cvector_size(comm, CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cload_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLOAD_NODE *cload_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cload_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_node: cload_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CLOAD_NODE_TCID(cload_node)));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CLOAD_NODE_COMM(cload_node)));
    cmpi_decode_cvector(comm, in_buff, in_buff_max_len, position,  (CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));

    return ((UINT32)0);
}

UINT32 cmpi_encode_cload_mgr(const UINT32 comm, const CLOAD_MGR *cload_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cload_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_mgr: cload_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_mgr: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cload_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, clist_size(cload_mgr), out_buff, out_buff_max_len, position);

    CLIST_LOCK(cload_mgr, LOC_CMPIE_0009);
    CLIST_LOOP_NEXT(cload_mgr, clist_data)
    {
        CLOAD_NODE *cload_node;
        cload_node = (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);
        cmpi_encode_cload_node(comm, cload_node, out_buff, out_buff_max_len, position);
    }
    CLIST_UNLOCK(cload_mgr, LOC_CMPIE_0010);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cload_mgr_size(const UINT32 comm, const CLOAD_MGR *cload_mgr, UINT32 *size)
{
    CLIST_DATA *clist_data;

    cmpi_encode_uint32_size(comm, clist_size(cload_mgr), size);

    CLIST_LOCK(cload_mgr, LOC_CMPIE_0011);
    CLIST_LOOP_NEXT(cload_mgr, clist_data)
    {
        CLOAD_NODE *cload_node;
        cload_node = (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);
        cmpi_encode_cload_node_size(comm, cload_node, size);
    }
    CLIST_UNLOCK(cload_mgr, LOC_CMPIE_0012);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cload_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLOAD_MGR *cload_mgr)
{
    UINT32 pos;
    UINT32 size;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_mgr: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cload_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cload_mgr: cload_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(size));
    for(pos = 0; pos < size; pos ++)
    {
        CLOAD_NODE *cload_node;
        cload_node = cload_node_new(CMPI_ERROR_TCID, CMPI_ERROR_COMM, 0);
        cmpi_decode_cload_node(comm, in_buff, in_buff_max_len, position, cload_node);
        clist_push_back(cload_mgr, (void *)cload_node);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_cbytes(const UINT32 comm, const CBYTES *cbytes, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
/*
    if ( NULL_PTR == cbytes )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cbytes: cbytes is null.\n");
        dbg_exit(MD_TBD, 0);
    }
*/
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cbytes: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cbytes: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    if(NULL_PTR == cbytes)
    {
        cmpi_encode_uint32(comm, 0, out_buff, out_buff_max_len, position);
        return ((UINT32)0);
    }

    cmpi_encode_uint8_array(comm, CBYTES_BUF(cbytes), CBYTES_LEN(cbytes), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cbytes_size(const UINT32 comm, const CBYTES *cbytes, UINT32 *size)
{
    if(NULL_PTR == cbytes)
    {
        cmpi_encode_uint32_size(comm, 0, size);
        return ((UINT32)0);
    }

    cmpi_encode_uint8_array_size(comm, NULL_PTR, CBYTES_LEN(cbytes), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cbytes(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CBYTES *cbytes)
{
    UINT32 len;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cbytes: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cbytes: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cbytes )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cbytes: cbytes is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &len);
    if(0 == len)
    {
        CBYTES_LEN(cbytes) = len;
        /*nothing to do*/
        return ((UINT32)0);
    }

    if(NULL_PTR == CBYTES_BUF(cbytes))
    {
        //dbg_log(SEC_0035_CMPIE, 1)(LOGSTDOUT, "warn:cmpi_decode_cbytes: len %ld but buff is null\n", len);
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(len, LOC_CMPIE_0013);
        CBYTES_LEN(cbytes) = len;
    }
    else
    {
        if(CBYTES_LEN(cbytes) < len)
        {
            dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cbytes: buff room is %ld bytes, no enough memory to accept %ld bytes\n", CBYTES_LEN(cbytes), len);
            return ((UINT32)-1);
        }
        CBYTES_LEN(cbytes) = len;
    }

    cmpi_unpack(in_buff, in_buff_max_len, position, CBYTES_BUF(cbytes), len, CMPI_UCHAR, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_ctimet(const UINT32 comm, const CTIMET *ctimet, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    char time_buf[64];
    CSTRING cstring;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == ctimet )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctimet: ctimet is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctimet: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctimet: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", c_localtime_r(ctimet));
    cstring_set_str(&cstring, (UINT8 *)time_buf);
    cmpi_encode_cstring(comm, &cstring, out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_ctimet_size(const UINT32 comm, const CTIMET *ctimet, UINT32 *size)
{
    char time_buf[64];
    CSTRING cstring;

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", c_localtime_r(ctimet));
    cstring_set_str(&cstring, (UINT8 *)time_buf);
    cmpi_encode_cstring_size(comm, &cstring, size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_ctimet(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CTIMET *ctimet)
{
    CSTRING cstring;
    struct tm tm_time;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctimet: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctimet: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == ctimet )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctimet: ctimet is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cstring_init(&cstring, NULL_PTR);

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, &cstring);
    strptime((char *)cstring_get_str(&cstring), "%Y-%m-%d %H:%M:%S", &tm_time);
    (*ctimet) = mktime(&tm_time);
    cstring_clean(&cstring);
    return ((UINT32)0);
}

UINT32 cmpi_encode_csession_node(const UINT32 comm, const CSESSION_NODE *csession_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == csession_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csession_node: csession_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csession_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csession_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CSESSION_NODE_NAME(csession_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSESSION_NODE_ID(csession_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CSESSION_NODE_EXPIRE_NSEC(csession_node), out_buff, out_buff_max_len, position);
    cmpi_encode_ctimet(comm, &CSESSION_NODE_CREATE_TIME(csession_node), out_buff, out_buff_max_len, position);
    cmpi_encode_ctimet(comm, &CSESSION_NODE_ACCESS_TIME(csession_node), out_buff, out_buff_max_len, position);
    cmpi_encode_clist(comm, CSESSION_NODE_CACHE_TREE(csession_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csession_node_size(const UINT32 comm, const CSESSION_NODE *csession_node, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CSESSION_NODE_NAME(csession_node), size);
    cmpi_encode_uint32_size(comm, CSESSION_NODE_ID(csession_node), size);
    cmpi_encode_uint32_size(comm, CSESSION_NODE_EXPIRE_NSEC(csession_node), size);
    cmpi_encode_ctimet_size(comm, &CSESSION_NODE_CREATE_TIME(csession_node), size);
    cmpi_encode_ctimet_size(comm, &CSESSION_NODE_ACCESS_TIME(csession_node), size);
    cmpi_encode_clist_size(comm, CSESSION_NODE_CACHE_TREE(csession_node), size);


    return ((UINT32)0);
}

UINT32 cmpi_decode_csession_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSESSION_NODE *csession_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csession_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csession_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == csession_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csession_node: csession_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSESSION_NODE_NAME(csession_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CSESSION_NODE_ID(csession_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CSESSION_NODE_EXPIRE_NSEC(csession_node));
    cmpi_decode_ctimet(comm, in_buff, in_buff_max_len, position, &CSESSION_NODE_CREATE_TIME(csession_node));
    cmpi_decode_ctimet(comm, in_buff, in_buff_max_len, position, &CSESSION_NODE_ACCESS_TIME(csession_node));
    cmpi_decode_clist(comm, in_buff, in_buff_max_len, position, CSESSION_NODE_CACHE_TREE(csession_node));

    return ((UINT32)0);
}

UINT32 cmpi_encode_csession_item(const UINT32 comm, const CSESSION_ITEM *csession_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == csession_item )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csession_item: csession_item is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csession_item: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_csession_item: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CSESSION_ITEM_KEY(csession_item), out_buff, out_buff_max_len, position);
    cmpi_encode_cbytes(comm, CSESSION_ITEM_VAL(csession_item), out_buff, out_buff_max_len, position);
    cmpi_encode_clist(comm, CSESSION_ITEM_CHILDREN(csession_item), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_csession_item_size(const UINT32 comm, const CSESSION_ITEM *csession_item, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CSESSION_ITEM_KEY(csession_item), size);
    cmpi_encode_cbytes_size(comm, CSESSION_ITEM_VAL(csession_item), size);
    cmpi_encode_clist_size(comm, CSESSION_ITEM_CHILDREN(csession_item), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_csession_item(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSESSION_ITEM *csession_item)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csession_item: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csession_item: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == csession_item )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_csession_item: csession_item is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSESSION_ITEM_KEY(csession_item));
    cmpi_decode_cbytes(comm, in_buff, in_buff_max_len, position, CSESSION_ITEM_VAL(csession_item));
    cmpi_decode_clist(comm, in_buff, in_buff_max_len, position, CSESSION_ITEM_CHILDREN(csession_item));

    return ((UINT32)0);
}

UINT32 cmpi_encode_clist(const UINT32 comm, const CLIST *clist, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32 size;
    UINT32 num;
    UINT32 type;

    CLIST_DATA_ENCODER data_encoder;
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == clist )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_clist: clist is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_clist: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_clist: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    type = clist_type(clist);
    size = clist_size(clist);

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_clist: clist %p, type = %ld, size = %ld, position = %ld\n",
                        clist, type, size, *position));

    cmpi_encode_uint32(comm, type, out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, size, out_buff, out_buff_max_len, position);

    if(0 == size)
    {
        return ((UINT32)0);
    }

    data_encoder = (CLIST_DATA_ENCODER)clist_codec_get(clist, CLIST_CODEC_ENCODER);
    if(NULL_PTR == data_encoder)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_clist: clist data encoder is null\n");
        return ((UINT32)-1);
    }

    num = 0;
    CLIST_LOCK(clist, LOC_CMPIE_0014);
    CLIST_LOOP_NEXT(clist, clist_data)
    {
        void *data;
        data = CLIST_DATA_DATA(clist_data);
        data_encoder(comm, data, out_buff, out_buff_max_len, position);
        num ++;
    }
    CLIST_UNLOCK(clist, LOC_CMPIE_0015);

    /*check again*/
    if(size != num)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_clist: clist size = %ld but encoded item num = %ld\n", size, num);
        return ((UINT32)-1);
    }

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_clist: clist %p, type = %ld, num = %ld ==> position = %ld\n",
                        clist, clist_type(clist), clist_size(clist), *position));

    return ((UINT32)0);
}

UINT32 cmpi_encode_clist_size(const UINT32 comm, const CLIST *clist, UINT32 *size)
{
    UINT32 num;
    UINT32 type;

    CLIST_DATA_ENCODER_SIZE data_encoder_size;

    type = clist_type(clist);
    num = clist_size(clist);

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_clist_size: clist %p: type = %ld, num = %ld, size = %ld\n", clist, type, num, *size));

    if(MM_END == type)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_clist_size: clist %p: invalid type = %ld, num = %ld\n", clist, type, num);
    }

    cmpi_encode_uint32_size(comm, type, size);
    cmpi_encode_uint32_size(comm, num, size);

    if(0 == num)
    {
        return ((UINT32)0);
    }

    data_encoder_size = (CLIST_DATA_ENCODER_SIZE)clist_codec_get(clist, CLIST_CODEC_ENCODER_SIZE);
    if(NULL_PTR == data_encoder_size)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_encode_clist_size: clist %p: type = %ld, num = %ld, data encoder_size is null\n",
                            clist, type, num);
        return ((UINT32)-1);
    }

    if(MM_UINT32 == type)
    {
        CLIST_DATA *clist_data;

        CLIST_LOCK(clist, LOC_CMPIE_0016);
        CLIST_LOOP_NEXT(clist, clist_data)
        {
            void *data;
            data = CLIST_DATA_DATA(clist_data);
            data_encoder_size(comm, data, size);
        }
        CLIST_UNLOCK(clist, LOC_CMPIE_0017);
    }
    else/*non UINT32*/
    {
        CLIST_DATA *clist_data;

        CLIST_LOCK(clist, LOC_CMPIE_0018);
        CLIST_LOOP_NEXT(clist, clist_data)
        {
            void *data;
            data = CLIST_DATA_DATA(clist_data);
            data_encoder_size(comm, data, size);
        }
        CLIST_UNLOCK(clist, LOC_CMPIE_0019);
    }

    CMPI_DBG((LOGSTDOUT, "info:cmpi_encode_clist_size: clist %p: type = %ld, num = %ld, ==> size %ld\n",
                            clist, clist_type(clist), clist_size(clist), *size));

    return ((UINT32)0);
}

UINT32 cmpi_decode_clist(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLIST *clist)
{
    UINT32 num;
    UINT32 type;

    UINT32 pos;
    CLIST_DATA_DECODER data_decoder;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_clist: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_clist: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == clist )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_clist: clist is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(type));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(num));

    dbg_log(SEC_0035_CMPIE, 3)(LOGSTDNULL, "info:cmpi_decode_clist: enter: clist %p, type = %ld, num = %ld, size = %ld\n", clist, type, num, clist->size);

    if(type != clist->data_mm_type)
    {
        dbg_log(SEC_0035_CMPIE, 3)(LOGSTDNULL, "info:cmpi_decode_clist: clist %p, data type %ld ==> %ld\n", clist, clist->data_mm_type, type);
        clist_codec_set(clist, type);
    }
    dbg_log(SEC_0035_CMPIE, 3)(LOGSTDNULL, "info:cmpi_decode_clist: [0] clist %p, data type %ld \n", clist, clist->data_mm_type);

    if(0 == num)
    {
        return ((UINT32)0);
    }

    data_decoder = (CLIST_DATA_DECODER)clist_codec_get(clist, CLIST_CODEC_DECODER);
    if(NULL_PTR == data_decoder)
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_clist: clist %p data decoder is null\n", clist);
        return ((UINT32)-1);
    }

    if(MM_UINT32 == type)
    {
        /*alloc new item to accept the decoded result, and push the new item*/
        for(pos = 0; pos < num; pos ++)
        {
            UINT32 data;

            data_decoder(comm, in_buff, in_buff_max_len, position, &data);
            clist_push_back(clist, (void *)data);/*add new one*/
        }
    }
    else/*non UINT32*/
    {
        CLIST_DATA_INIT    data_init;

        data_init = (CLIST_DATA_INIT)clist_codec_get(clist, CLIST_CODEC_INIT);/*data_init may be null pointer*/
        if(NULL_PTR == data_init)
        {
            dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_clist: clist %p data init is null\n", clist);
            return ((UINT32)-1);
        }
        /*alloc new item to accept the decoded result, and push the new item*/
        for(pos = 0; pos < num; pos ++)
        {
            void * data;

            alloc_static_mem(type, &data, LOC_CMPIE_0020);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_clist: [3] clist %p, size %ld, pos = %ld failed to alloc\n",
                                    clist, clist->size, pos);
                return ((UINT32)-1);
            }
            data_init(data);
            data_decoder(comm, in_buff, in_buff_max_len, position, data);
            clist_push_back(clist, (void *)data);/*add new one*/
        }
    }
    CMPI_DBG((LOGSTDOUT, "info:cmpi_decode_clist: leave: clist %p, type = %ld, num = %ld, size = %ld\n", clist, type, num, clist->size));
    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_inode(const UINT32 comm, const CRFSNP_INODE *crfsnp_inode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crfsnp_inode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_inode: crfsnp_inode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_inode: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_inode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint16(comm, CRFSNP_INODE_DISK_NO(crfsnp_inode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint16(comm, CRFSNP_INODE_BLOCK_NO(crfsnp_inode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint16(comm, CRFSNP_INODE_PAGE_NO(crfsnp_inode), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_inode_size(const UINT32 comm, const CRFSNP_INODE *crfsnp_inode, UINT32 *size)
{
    cmpi_encode_uint16_size(comm, CRFSNP_INODE_DISK_NO(crfsnp_inode), size);
    cmpi_encode_uint16_size(comm, CRFSNP_INODE_BLOCK_NO(crfsnp_inode), size);
    cmpi_encode_uint16_size(comm, CRFSNP_INODE_PAGE_NO(crfsnp_inode), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_crfsnp_inode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRFSNP_INODE *crfsnp_inode)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_inode: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_inode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crfsnp_inode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_inode: crfsnp_inode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CRFSNP_INODE_DISK_NO(crfsnp_inode)));
    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CRFSNP_INODE_BLOCK_NO(crfsnp_inode)));
    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CRFSNP_INODE_PAGE_NO(crfsnp_inode)));

    return ((UINT32)0);
}


UINT32 cmpi_encode_crfsnp_fnode(const UINT32 comm, const CRFSNP_FNODE *crfsnp_fnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    uint32_t crfsnp_inode_pos;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crfsnp_fnode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_fnode: crfsnp_fnode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_fnode: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_fnode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CRFSNP_FNODE_FILESZ(crfsnp_fnode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_FNODE_REPNUM(crfsnp_fnode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_FNODE_HASH(crfsnp_fnode), out_buff, out_buff_max_len, position);

    for(crfsnp_inode_pos = 0; crfsnp_inode_pos < (CRFSNP_FNODE_REPNUM(crfsnp_fnode)) && crfsnp_inode_pos < CRFSNP_FILE_REPLICA_MAX_NUM; crfsnp_inode_pos ++)
    {
        CRFSNP_INODE *crfsnp_inode;

        crfsnp_inode = (CRFSNP_INODE *)CRFSNP_FNODE_INODE(crfsnp_fnode, crfsnp_inode_pos);
        cmpi_encode_crfsnp_inode(comm, crfsnp_inode, out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_fnode_size(const UINT32 comm, const CRFSNP_FNODE *crfsnp_fnode, UINT32 *size)
{
    uint32_t crfsnp_inode_pos;

    cmpi_encode_uint32_t_size(comm, CRFSNP_FNODE_FILESZ(crfsnp_fnode), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_FNODE_REPNUM(crfsnp_fnode), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_FNODE_HASH(crfsnp_fnode), size);

    for(crfsnp_inode_pos = 0; crfsnp_inode_pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode) && crfsnp_inode_pos < CRFSNP_FILE_REPLICA_MAX_NUM; crfsnp_inode_pos ++)
    {
        CRFSNP_INODE *crfsnp_inode;

        crfsnp_inode = (CRFSNP_INODE *)CRFSNP_FNODE_INODE(crfsnp_fnode, crfsnp_inode_pos);
        cmpi_encode_crfsnp_inode_size(comm, crfsnp_inode, size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_crfsnp_fnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t file_size;
    uint32_t replica_num;
    uint32_t hash;

    uint32_t crfsnp_inode_pos;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_fnode: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_fnode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crfsnp_fnode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_fnode: crfsnp_fnode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(file_size));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(replica_num));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(hash));

    if(CRFSNP_FILE_REPLICA_MAX_NUM < (replica_num))
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_crfsnp_fnode: replica num %ld overflow\n", replica_num);
        return ((UINT32)-1);
    }

    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = (uint32_t)(file_size);
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = (uint32_t)(replica_num);
    CRFSNP_FNODE_HASH(crfsnp_fnode)   = (uint32_t)(hash);

    for(crfsnp_inode_pos = 0; crfsnp_inode_pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode); crfsnp_inode_pos ++)
    {
        CRFSNP_INODE *crfsnp_inode;

        crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, crfsnp_inode_pos);
        cmpi_decode_crfsnp_inode(comm, in_buff, in_buff_max_len, position, crfsnp_inode);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_key(const UINT32 comm, const CRFSNP_KEY *crfsnp_key, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crfsnp_key )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_key: crfsnp_key is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_key: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_key: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint8(comm, CRFSNP_KEY_LEN(crfsnp_key), out_buff, out_buff_max_len, position);
    cmpi_pack(CRFSNP_KEY_NAME(crfsnp_key), CRFSNP_KEY_LEN(crfsnp_key), CMPI_UCHAR, out_buff, out_buff_max_len, position, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_key_size(const UINT32 comm, const CRFSNP_KEY *crfsnp_key, UINT32 *size)
{
    cmpi_encode_uint8_size(comm, CRFSNP_KEY_LEN(crfsnp_key), size);
    cmpi_pack_size(CRFSNP_KEY_LEN(crfsnp_key), CMPI_UCHAR, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_crfsnp_key(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRFSNP_KEY *crfsnp_key)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_key: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_key: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crfsnp_key )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_key: crfsnp_key is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &CRFSNP_KEY_LEN(crfsnp_key));
    cmpi_unpack(in_buff, in_buff_max_len, position, CRFSNP_KEY_NAME(crfsnp_key), CRFSNP_KEY_LEN(crfsnp_key), CMPI_UCHAR, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnplru_node(const UINT32 comm, const CRFSNPLRU_NODE *crfsnplru_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crfsnplru_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnplru_node: crfsnplru_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnplru_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnplru_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CRFSNPLRU_NODE_PREV_POS(crfsnplru_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNPLRU_NODE_NEXT_POS(crfsnplru_node), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnplru_node_size(const UINT32 comm, const CRFSNPLRU_NODE *crfsnplru_node, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CRFSNPLRU_NODE_PREV_POS(crfsnplru_node), size);
    cmpi_encode_uint32_t_size(comm, CRFSNPLRU_NODE_NEXT_POS(crfsnplru_node), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_crfsnplru_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRFSNPLRU_NODE *crfsnplru_node)
{
    uint32_t num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnplru_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnplru_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crfsnplru_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnplru_node: crfsnplru_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNPLRU_NODE_PREV_POS(crfsnplru_node) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNPLRU_NODE_NEXT_POS(crfsnplru_node)  = num;

    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnpdel_node(const UINT32 comm, const CRFSNPDEL_NODE *crfsnpdel_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crfsnpdel_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnpdel_node: crfsnpdel_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnpdel_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnpdel_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CRFSNPDEL_NODE_PREV_POS(crfsnpdel_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNPDEL_NODE_NEXT_POS(crfsnpdel_node), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnpdel_node_size(const UINT32 comm, const CRFSNPDEL_NODE *crfsnpdel_node, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CRFSNPDEL_NODE_PREV_POS(crfsnpdel_node), size);
    cmpi_encode_uint32_t_size(comm, CRFSNPDEL_NODE_NEXT_POS(crfsnpdel_node), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_crfsnpdel_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRFSNPDEL_NODE *crfsnpdel_node)
{
    uint32_t num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnpdel_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnpdel_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crfsnpdel_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnpdel_node: crfsnpdel_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNPDEL_NODE_PREV_POS(crfsnpdel_node) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNPDEL_NODE_NEXT_POS(crfsnpdel_node)  = num;

    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_item(const UINT32 comm, const CRFSNP_ITEM *crfsnp_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == crfsnp_item )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_item: crfsnp_item is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_item: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_crfsnp_item: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CRFSNP_ITEM_USED_FLAG(crfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_ITEM_DIR_FLAG(crfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_ITEM_CREATE_TIME(crfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_ITEM_KEY_OFFSET(crfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_ITEM_PARENT_POS(crfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CRFSNP_ITEM_SECOND_HASH(crfsnp_item), out_buff, out_buff_max_len, position);

    cmpi_encode_crfsnplru_node(comm, CRFSNP_ITEM_LRU_NODE(crfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_crfsnpdel_node(comm, CRFSNP_ITEM_DEL_NODE(crfsnp_item), out_buff, out_buff_max_len, position);

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cmpi_encode_uint32_t(comm, CRFSNP_DNODE_FILE_NUM(CRFSNP_ITEM_DNODE(crfsnp_item)), out_buff, out_buff_max_len, position);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cmpi_encode_crfsnp_fnode(comm, CRFSNP_ITEM_FNODE(crfsnp_item), out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_crfsnp_item_size(const UINT32 comm, const CRFSNP_ITEM *crfsnp_item, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CRFSNP_ITEM_USED_FLAG(crfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_ITEM_DIR_FLAG(crfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_ITEM_CREATE_TIME(crfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_ITEM_KEY_OFFSET(crfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_ITEM_PARENT_POS(crfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CRFSNP_ITEM_SECOND_HASH(crfsnp_item), size);

    cmpi_encode_crfsnplru_node_size(comm, CRFSNP_ITEM_LRU_NODE(crfsnp_item), size);
    cmpi_encode_crfsnpdel_node_size(comm, CRFSNP_ITEM_DEL_NODE(crfsnp_item), size);

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cmpi_encode_uint32_t_size(comm, CRFSNP_DNODE_FILE_NUM(CRFSNP_ITEM_DNODE(crfsnp_item)), size);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cmpi_encode_crfsnp_fnode_size(comm, CRFSNP_ITEM_FNODE(crfsnp_item), size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_crfsnp_item(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRFSNP_ITEM *crfsnp_item)
{
    uint32_t num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_item: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_item: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == crfsnp_item )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_crfsnp_item: crfsnp_item is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNP_ITEM_USED_FLAG(crfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNP_ITEM_DIR_FLAG(crfsnp_item)  = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNP_ITEM_CREATE_TIME(crfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNP_ITEM_KEY_OFFSET(crfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNP_ITEM_PARENT_POS(crfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CRFSNP_ITEM_SECOND_HASH(crfsnp_item) = num;

    cmpi_decode_crfsnplru_node(comm, in_buff, in_buff_max_len, position, CRFSNP_ITEM_LRU_NODE(crfsnp_item));
    cmpi_decode_crfsnpdel_node(comm, in_buff, in_buff_max_len, position, CRFSNP_ITEM_DEL_NODE(crfsnp_item));

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
        CRFSNP_DNODE_FILE_NUM(CRFSNP_ITEM_DNODE(crfsnp_item)) = num;
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cmpi_decode_crfsnp_fnode(comm, in_buff, in_buff_max_len, position, CRFSNP_ITEM_FNODE(crfsnp_item));
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_time_t(const UINT32 comm, const ctime_t time, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_time_t: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_time_t: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, (UINT32)time, out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_time_t_size(const UINT32 comm, const ctime_t time, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, (UINT32)time, size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_time_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, ctime_t *time)
{
    UINT32 tmp;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_time_t: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_time_t: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == time )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_time_t: ctimet is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(tmp));
    (*time) = (time_t)tmp;

    return ((UINT32)0);
}

UINT32 cmpi_encode_cmd5_digest(const UINT32 comm, const CMD5_DIGEST *cmd5_digest, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cmd5_digest )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cmd5_digest: cmd5_digest is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cmd5_digest: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cmd5_digest: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint8_array(comm, CMD5_DIGEST_SUM(cmd5_digest), CMD5_DIGEST_LEN, out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cmd5_digest_size(const UINT32 comm, const CMD5_DIGEST *cmd5_digest, UINT32 *size)
{
    cmpi_encode_uint8_array_size(comm, CMD5_DIGEST_SUM(cmd5_digest), CMD5_DIGEST_LEN, size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cmd5_digest(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CMD5_DIGEST *cmd5_digest)
{
    UINT32 size;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cmd5_digest: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cmd5_digest: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cmd5_digest )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cmd5_digest: cmd5_digest is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, CMD5_DIGEST_SUM(cmd5_digest), &(size));
    ASSERT(CMD5_DIGEST_LEN == size);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cbuffer(const UINT32 comm, const CBUFFER *cbuffer, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    uint32_t used_size;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cbuffer )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cbuffer: cbuffer is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cbuffer: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cbuffer: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    used_size = CBUFFER_USED(cbuffer);
    cmpi_pack((UINT8 *)&(used_size), 1, CMPI_U32, out_buff, out_buff_max_len, position,  comm);
    cmpi_pack(CBUFFER_DATA(cbuffer), CBUFFER_USED(cbuffer), CMPI_UCHAR, out_buff, out_buff_max_len, position,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cbuffer_size(const UINT32 comm, const CBUFFER *cbuffer, UINT32 *size)
{
    (*size) += CBUFFER_USED(cbuffer);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cbuffer(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CBUFFER *cbuffer)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cbuffer: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cbuffer: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cbuffer )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cbuffer: cbuffer is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    uint32_t used_size;

    cmpi_unpack(in_buff, in_buff_max_len, position, (UINT8 *)&used_size, 1,   CMPI_U32, comm);

    cbuffer_expand_to(cbuffer, used_size);
    cmpi_unpack(in_buff, in_buff_max_len, position, CBUFFER_DATA(cbuffer) + CBUFFER_USED(cbuffer), used_size, CMPI_UCHAR, comm);
    CBUFFER_USED(cbuffer) += used_size;

    return ((UINT32)0);
}

#if 1
UINT32 cmpi_encode_cstrkv(const UINT32 comm, const CSTRKV *cstrkv, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cstrkv )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstrkv: cstrkv is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstrkv: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstrkv: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CSTRKV_KEY(cstrkv), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CSTRKV_VAL(cstrkv), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cstrkv_size(const UINT32 comm, const CSTRKV *cstrkv, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CSTRKV_KEY(cstrkv), size);
    cmpi_encode_cstring_size(comm, CSTRKV_VAL(cstrkv), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cstrkv(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSTRKV *cstrkv)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cstrkv )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv: cstrkv is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSTRKV_KEY(cstrkv));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CSTRKV_VAL(cstrkv));

    return ((UINT32)0);
}

#endif


#if 1
UINT32 cmpi_encode_cstrkv_mgr(const UINT32 comm, const CSTRKV_MGR *cstrkv_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    CLIST      *kv_list;
    CLIST_DATA *clist_data;

    UINT32      len;
    UINT32      idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cstrkv_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstrkv_mgr: cstrkv_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstrkv_mgr: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cstrkv_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */
    if(NULL_PTR == cstrkv_mgr)
    {
        cmpi_encode_uint32(comm, (UINT32)0, out_buff, out_buff_max_len, position);
        return ((UINT32)0);
    }

    kv_list = (CLIST *)CSTRKV_MGR_LIST(cstrkv_mgr);
    len     = clist_size(kv_list);

    cmpi_encode_uint32(comm, (UINT32)len, out_buff, out_buff_max_len, position);

    idx = 0;
    CLIST_LOOP_NEXT(kv_list, clist_data)
    {
        CSTRKV *cstrkv;

        idx ++;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }
        //dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_encode_cstrkv_mgr: [%ld/%ld] position: %ld, cstrkv: %p => beg\n", idx, len, (*position), cstrkv);
        //cstrkv_print(LOGSTDOUT, cstrkv);
        cmpi_encode_cstrkv(comm, cstrkv, out_buff, out_buff_max_len, position);
        //dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_encode_cstrkv_mgr: [%ld/%ld] position: %ld, cstrkv: %p => end\n", idx, len, (*position), cstrkv);
    }

    ASSERT(idx == len);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cstrkv_mgr_size(const UINT32 comm, const CSTRKV_MGR *cstrkv_mgr, UINT32 *size)
{
    CLIST      *kv_list;
    CLIST_DATA *clist_data;

    UINT32      len;
    UINT32      idx;

    if(NULL_PTR == cstrkv_mgr)
    {
        cmpi_encode_uint32_size(comm, (UINT32)0, size);
        return ((UINT32)0);
    }

    kv_list = (CLIST *)CSTRKV_MGR_LIST(cstrkv_mgr);
    len     = clist_size(kv_list);

    cmpi_encode_uint32_size(comm, (UINT32)len, size);

    idx = 0;
    CLIST_LOOP_NEXT(kv_list, clist_data)
    {
        CSTRKV *cstrkv;

        idx ++;

        cstrkv = (CSTRKV *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_encode_cstrkv_mgr_size: [%ld/%ld] size: %ld, cstrkv: %p => beg\n", idx, len, (*size), cstrkv);
        //cstrkv_print(LOGSTDOUT, cstrkv);
        cmpi_encode_cstrkv_size(comm, cstrkv, size);
        //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_encode_cstrkv_mgr_size: [%ld/%ld] size: %ld, cstrkv: %p => end\n", idx, len, (*size), cstrkv);
    }

    ASSERT(idx == len);

    return ((UINT32)0);
}

UINT32 cmpi_decode_cstrkv_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSTRKV_MGR *cstrkv_mgr)
{
    UINT32 len;
    UINT32 idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv_mgr: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cstrkv_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv_mgr: cstrkv_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    ASSERT(0 == cstrkv_mgr_size(cstrkv_mgr));

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &len);

    for(idx = 0; idx < len; idx ++)
    {
        CSTRKV *cstrkv;

        cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
        if(NULL_PTR == cstrkv)
        {
            dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cstrkv_mgr: new cstrkv failed where idx = %ld, len = %ld\n", idx, len);
            dbg_exit(MD_TBD, 0);
        }

        //dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_decode_cstrkv_mgr: [%ld/%ld] position: %ld, cstrkv: %p => beg\n", idx, len, (*position), cstrkv);
        cmpi_decode_cstrkv(comm, in_buff, in_buff_max_len, position, cstrkv);
        //cstrkv_print(LOGSTDOUT, cstrkv);
        //dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_decode_cstrkv_mgr: [%ld/%ld] position: %ld, cstrkv: %p => end\n", idx, len, (*position), cstrkv);

        cstrkv_mgr_add_kv(cstrkv_mgr, cstrkv);
    }

    ASSERT(len == cstrkv_mgr_size(cstrkv_mgr));
    return ((UINT32)0);
}

#endif


#if 1
UINT32 cmpi_encode_chttp_req(const UINT32 comm, const CHTTP_REQ *chttp_req, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == chttp_req )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_req: chttp_req is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_req: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_req: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, CHTTP_REQ_IPADDR(chttp_req), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CHTTP_REQ_PORT(chttp_req), out_buff, out_buff_max_len, position);

#if (SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)
    cmpi_encode_cstring(comm, CHTTP_REQ_DOMAIN(chttp_req), out_buff, out_buff_max_len, position);
#endif /*(SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)*/

    cmpi_encode_cstring(comm, CHTTP_REQ_DEVICE_NAME(chttp_req), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_REQ_TRACE_ID(chttp_req), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32(comm, CHTTP_REQ_SSL_FLAG(chttp_req), out_buff, out_buff_max_len, position);

    cmpi_encode_cstring(comm, CHTTP_REQ_METHOD(chttp_req), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_REQ_URI(chttp_req), out_buff, out_buff_max_len, position);

    cmpi_encode_cstrkv_mgr(comm, CHTTP_REQ_PARAM(chttp_req), out_buff, out_buff_max_len, position);
    cmpi_encode_cstrkv_mgr(comm, CHTTP_REQ_HEADER(chttp_req), out_buff, out_buff_max_len, position);

    cmpi_encode_cbytes(comm, CHTTP_REQ_BODY(chttp_req), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_chttp_req_size(const UINT32 comm, const CHTTP_REQ *chttp_req, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, CHTTP_REQ_IPADDR(chttp_req), size);
    cmpi_encode_uint32_size(comm, CHTTP_REQ_PORT(chttp_req), size);

#if (SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)
    cmpi_encode_cstring_size(comm, CHTTP_REQ_DOMAIN(chttp_req), size);
#endif/*(SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)*/

    cmpi_encode_cstring_size(comm, CHTTP_REQ_DEVICE_NAME(chttp_req), size);
    cmpi_encode_cstring_size(comm, CHTTP_REQ_TRACE_ID(chttp_req), size);

    cmpi_encode_uint32_size(comm, CHTTP_REQ_SSL_FLAG(chttp_req), size);

    cmpi_encode_cstring_size(comm, CHTTP_REQ_METHOD(chttp_req), size);
    cmpi_encode_cstring_size(comm, CHTTP_REQ_URI(chttp_req), size);

    cmpi_encode_cstrkv_mgr_size(comm, CHTTP_REQ_PARAM(chttp_req), size);
    cmpi_encode_cstrkv_mgr_size(comm, CHTTP_REQ_HEADER(chttp_req), size);

    cmpi_encode_cbytes_size(comm, CHTTP_REQ_BODY(chttp_req), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_chttp_req(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_REQ *chttp_req)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_req: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_req: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == chttp_req )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_req: chttp_req is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_REQ_IPADDR(chttp_req));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_REQ_PORT(chttp_req));

#if (SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_DOMAIN(chttp_req));
#endif/*(SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)*/

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_DEVICE_NAME(chttp_req));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_TRACE_ID(chttp_req));

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_REQ_SSL_FLAG(chttp_req));

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_METHOD(chttp_req));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_URI(chttp_req));

    cmpi_decode_cstrkv_mgr(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_PARAM(chttp_req));
    cmpi_decode_cstrkv_mgr(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_HEADER(chttp_req));

    cmpi_decode_cbytes(comm, in_buff, in_buff_max_len, position, CHTTP_REQ_BODY(chttp_req));

    return ((UINT32)0);
}
#endif

#if 1
UINT32 cmpi_encode_chttp_rsp(const UINT32 comm, const CHTTP_RSP *chttp_rsp, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == chttp_rsp )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_rsp: chttp_rsp is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_rsp: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_rsp: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT,"[DEBUG]cmpi_encode_chttp_rsp: position: %ld => beg\n", (*position));
    cmpi_encode_cstrkv_mgr(comm, CHTTP_RSP_HEADER(chttp_rsp), out_buff, out_buff_max_len, position);
    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT,"[DEBUG]cmpi_encode_chttp_rsp: position: %ld => header ok\n", (*position));

    cmpi_encode_cbytes(comm, CHTTP_RSP_BODY(chttp_rsp), out_buff, out_buff_max_len, position);
    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT,"[DEBUG]cmpi_encode_chttp_rsp: position: %ld => end\n", (*position));
    return ((UINT32)0);
}

UINT32 cmpi_encode_chttp_rsp_size(const UINT32 comm, const CHTTP_RSP *chttp_rsp, UINT32 *size)
{
    cmpi_encode_cstrkv_mgr_size(comm, CHTTP_RSP_HEADER(chttp_rsp), size);

    cmpi_encode_cbytes_size(comm, CHTTP_RSP_BODY(chttp_rsp), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_chttp_rsp(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_RSP *chttp_rsp)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_rsp: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_rsp: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == chttp_rsp )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_rsp: chttp_rsp is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT,"[DEBUG]cmpi_decode_chttp_rsp: position: %ld => beg\n", (*position));
    cmpi_decode_cstrkv_mgr(comm, in_buff, in_buff_max_len, position, CHTTP_RSP_HEADER(chttp_rsp));

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT,"[DEBUG]cmpi_decode_chttp_rsp: position: %ld => header ok\n", (*position));

    cmpi_decode_cbytes(comm, in_buff, in_buff_max_len, position, CHTTP_RSP_BODY(chttp_rsp));
    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT,"[DEBUG]cmpi_decode_chttp_rsp: position: %ld => end\n", (*position));

    return ((UINT32)0);
}
#endif

#if 1
UINT32 cmpi_encode_chttp_stat(const UINT32 comm, const CHTTP_STAT *chttp_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == chttp_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_stat: chttp_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_stat: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CHTTP_STAT_RSP_STATUS(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32_t(comm, CHTTP_STAT_S_SEND_LEN(chttp_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STAT_S_RECV_LEN(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_REQ_S_MSEC(chttp_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint64(comm, CHTTP_STAT_REQ_E_MSEC(chttp_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint64(comm, CHTTP_STAT_REQ_C_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_RSP_S_MSEC(chttp_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint64(comm, CHTTP_STAT_RSP_E_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32_t(comm, CHTTP_STAT_SSL_SHAKEHAND_MSEC(chttp_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STAT_SSL_SEND_LEN(chttp_stat), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STAT_CLIENT_RTT_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint8_array(comm, CHTTP_STAT_DEVICE_NAME(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, out_buff, out_buff_max_len, position);
    cmpi_encode_uint8_array(comm, CHTTP_STAT_TRACE_ID(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, out_buff, out_buff_max_len, position);

    cmpi_encode_uint8_array(comm, CHTTP_STAT_REQ_HOST(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, out_buff, out_buff_max_len, position);
    cmpi_encode_uint64(comm, CHTTP_STAT_REQ_IPADDR(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_LOG_BITMAP(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_BASIC_S_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_BASIC_R_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_BASIC_L_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_BASIC_H_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_BASIC_D_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    cmpi_encode_uint64(comm, CHTTP_STAT_BASIC_E_MSEC(chttp_stat), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_chttp_stat_size(const UINT32 comm, const CHTTP_STAT *chttp_stat, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CHTTP_STAT_RSP_STATUS(chttp_stat), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STAT_S_SEND_LEN(chttp_stat), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STAT_S_RECV_LEN(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_REQ_S_MSEC(chttp_stat), size);
    cmpi_encode_uint64_size(comm, CHTTP_STAT_REQ_E_MSEC(chttp_stat), size);
    cmpi_encode_uint64_size(comm, CHTTP_STAT_REQ_C_MSEC(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_RSP_S_MSEC(chttp_stat), size);
    cmpi_encode_uint64_size(comm, CHTTP_STAT_RSP_E_MSEC(chttp_stat), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STAT_SSL_SHAKEHAND_MSEC(chttp_stat), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STAT_SSL_SEND_LEN(chttp_stat), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STAT_CLIENT_RTT_MSEC(chttp_stat), size);

    cmpi_encode_uint8_array_size(comm, CHTTP_STAT_DEVICE_NAME(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, size);
    cmpi_encode_uint8_array_size(comm, CHTTP_STAT_TRACE_ID(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, size);

    cmpi_encode_uint8_array_size(comm, CHTTP_STAT_REQ_HOST(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, size);
    cmpi_encode_uint64_size(comm, CHTTP_STAT_REQ_IPADDR(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_LOG_BITMAP(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_BASIC_S_MSEC(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_BASIC_R_MSEC(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_BASIC_L_MSEC(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_BASIC_H_MSEC(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_BASIC_D_MSEC(chttp_stat), size);

    cmpi_encode_uint64_size(comm, CHTTP_STAT_BASIC_E_MSEC(chttp_stat), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_chttp_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_STAT *chttp_stat)
{
    UINT32      len;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_stat: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_stat: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == chttp_stat )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_stat: chttp_stat is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_RSP_STATUS(chttp_stat));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_S_SEND_LEN(chttp_stat));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_S_RECV_LEN(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_REQ_S_MSEC(chttp_stat));
    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_REQ_E_MSEC(chttp_stat));
    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_REQ_C_MSEC(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_RSP_S_MSEC(chttp_stat));
    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_RSP_E_MSEC(chttp_stat));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_SSL_SHAKEHAND_MSEC(chttp_stat));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_SSL_SEND_LEN(chttp_stat));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_CLIENT_RTT_MSEC(chttp_stat));

    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, CHTTP_STAT_DEVICE_NAME(chttp_stat), &len);
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, CHTTP_STAT_TRACE_ID(chttp_stat), &len);

    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, CHTTP_STAT_REQ_HOST(chttp_stat), &len);
    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_REQ_IPADDR(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_LOG_BITMAP(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_BASIC_S_MSEC(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_BASIC_R_MSEC(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_BASIC_L_MSEC(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_BASIC_H_MSEC(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_BASIC_D_MSEC(chttp_stat));

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STAT_BASIC_E_MSEC(chttp_stat));

    return ((UINT32)0);
}
#endif

#if 1
UINT32 cmpi_encode_chttp_store(const UINT32 comm, const CHTTP_STORE *chttp_store, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == chttp_store )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_store: chttp_store is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_store: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_chttp_store: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_encode_chttp_store: position: %ld, chttp_store: %p => beg\n", (*position), chttp_store);

    cmpi_encode_uint32_t(comm, CHTTP_STORE_SEG_MAX_ID(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_SEG_ID(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_SEG_SIZE(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_SEG_S_OFFSET(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_SEG_E_OFFSET(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_BASEDIR(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_BILLING_FLAGS(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_BILLING_DOMAIN(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_BILLING_CLIENT_TYPE(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_CACHE_CTRL(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_CACHE_DONE(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_MERGE_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_NEED_LOG_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_LOCKED_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_EXPIRED_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_CHUNK_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_AUTH_TOKEN(chttp_store), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32_t(comm, CHTTP_STORE_LAST_MODIFIED_SWITCH(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_ETAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_LAST_MODIFIED(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint64(comm, CHTTP_STORE_CONTENT_LENGTH(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_USE_GZIP_FLAG(chttp_store), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32_t(comm, CHTTP_STORE_CACHE_ALLOW(chttp_store), out_buff, out_buff_max_len, position);

    cmpi_encode_cstring(comm, CHTTP_STORE_CACHE_HTTP_CODES(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_NCACHE_HTTP_CODES(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_CACHE_RSP_HEADERS(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_NCACHE_RSP_HEADERS(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CHTTP_STORE_CACHE_IF_HTTP_CODES(chttp_store), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32_t(comm, CHTTP_STORE_OVERRIDE_EXPIRES_FLAG(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_OVERRIDE_EXPIRES_NSEC(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_DEFAULT_EXPIRES_NSEC(chttp_store), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32_t(comm, CHTTP_STORE_ORIG_TIMEOUT_NSEC(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CHTTP_STORE_REDIRECT_CTRL(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store), out_buff, out_buff_max_len, position);

    cmpi_encode_uint32(comm, CHTTP_STORE_BGN_ORIG_MOID(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CHTTP_STORE_BGN_IMPORT_HEADER_CALLBACK(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CHTTP_STORE_BGN_SEND_HEADER_CALLBACK(chttp_store), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CHTTP_STORE_BGN_SEND_BODY_CALLBACK(chttp_store), out_buff, out_buff_max_len, position);

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_encode_chttp_store: position: %ld, chttp_store: %p => end\n", (*position), chttp_store);
    return ((UINT32)0);
}

UINT32 cmpi_encode_chttp_store_size(const UINT32 comm, const CHTTP_STORE *chttp_store, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_SEG_MAX_ID(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_SEG_ID(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_SEG_SIZE(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_SEG_S_OFFSET(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_SEG_E_OFFSET(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_BASEDIR(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_BILLING_FLAGS(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_BILLING_DOMAIN(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_BILLING_CLIENT_TYPE(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_CACHE_CTRL(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_CACHE_DONE(chttp_store), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_MERGE_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_NEED_LOG_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_LOCKED_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_EXPIRED_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_CHUNK_FLAG(chttp_store), size);

    cmpi_encode_cstring_size(comm, CHTTP_STORE_AUTH_TOKEN(chttp_store), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_LAST_MODIFIED_SWITCH(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_ETAG(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_LAST_MODIFIED(chttp_store), size);
    cmpi_encode_uint64_size(comm, CHTTP_STORE_CONTENT_LENGTH(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_USE_GZIP_FLAG(chttp_store), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_CACHE_ALLOW(chttp_store), size);

    cmpi_encode_cstring_size(comm, CHTTP_STORE_CACHE_HTTP_CODES(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_NCACHE_HTTP_CODES(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_CACHE_RSP_HEADERS(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_NCACHE_RSP_HEADERS(chttp_store), size);
    cmpi_encode_cstring_size(comm, CHTTP_STORE_CACHE_IF_HTTP_CODES(chttp_store), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_OVERRIDE_EXPIRES_FLAG(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_OVERRIDE_EXPIRES_NSEC(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_DEFAULT_EXPIRES_NSEC(chttp_store), size);

    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_ORIG_TIMEOUT_NSEC(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store), size);
    cmpi_encode_uint32_t_size(comm, CHTTP_STORE_REDIRECT_CTRL(chttp_store), size);
    cmpi_encode_uint32_size(comm, CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store), size);

    cmpi_encode_uint32_size(comm, CHTTP_STORE_BGN_ORIG_MOID(chttp_store), size);
    cmpi_encode_uint32_size(comm, CHTTP_STORE_BGN_IMPORT_HEADER_CALLBACK(chttp_store), size);
    cmpi_encode_uint32_size(comm, CHTTP_STORE_BGN_SEND_HEADER_CALLBACK(chttp_store), size);
    cmpi_encode_uint32_size(comm, CHTTP_STORE_BGN_SEND_BODY_CALLBACK(chttp_store), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_chttp_store(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_STORE *chttp_store)
{
    uint32_t    flag;
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_store: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_store: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == chttp_store )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_chttp_store: chttp_store is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_decode_chttp_store: position: %ld, chttp_store: %p => beg\n", (*position), chttp_store);

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_SEG_MAX_ID(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_SEG_ID(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_SEG_SIZE(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_SEG_S_OFFSET(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_SEG_E_OFFSET(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_BASEDIR(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_BILLING_FLAGS(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_BILLING_DOMAIN(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_BILLING_CLIENT_TYPE(chttp_store));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_CACHE_CTRL(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_CACHE_DONE(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_MERGE_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_NEED_LOG_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_LOCKED_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_EXPIRED_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_CHUNK_FLAG(chttp_store) = flag;

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_AUTH_TOKEN(chttp_store));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_LAST_MODIFIED_SWITCH(chttp_store) = flag;

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_ETAG(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_LAST_MODIFIED(chttp_store));
    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_CONTENT_LENGTH(chttp_store));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_USE_GZIP_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_CACHE_ALLOW(chttp_store) = flag;

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_CACHE_HTTP_CODES(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_NCACHE_HTTP_CODES(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_CACHE_RSP_HEADERS(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_NCACHE_RSP_HEADERS(chttp_store));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CHTTP_STORE_CACHE_IF_HTTP_CODES(chttp_store));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_OVERRIDE_EXPIRES_FLAG(chttp_store) = flag;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_OVERRIDE_EXPIRES_NSEC(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_DEFAULT_EXPIRES_NSEC(chttp_store));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_ORIG_TIMEOUT_NSEC(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store));

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(flag));
    CHTTP_STORE_REDIRECT_CTRL(chttp_store) = flag;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store));

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_BGN_ORIG_MOID(chttp_store));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_BGN_IMPORT_HEADER_CALLBACK(chttp_store));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_BGN_SEND_HEADER_CALLBACK(chttp_store));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CHTTP_STORE_BGN_SEND_BODY_CALLBACK(chttp_store));

    //rlog(SEC_0035_CMPIE, 0)(LOGSTDOUT, "[DEBUG] cmpi_decode_chttp_store: position: %ld, chttp_store: %p => end\n", (*position), chttp_store);
    return ((UINT32)0);
}
#endif

#if 1
UINT32 cmpi_encode_tasks_node(const UINT32 comm, const TASKS_NODE *tasks_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == tasks_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_tasks_node: tasks_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_tasks_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_tasks_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, TASKS_NODE_SRVIPADDR(tasks_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASKS_NODE_SRVPORT(tasks_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASKS_NODE_TCID(tasks_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASKS_NODE_COMM(tasks_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, TASKS_NODE_SIZE(tasks_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_tasks_node_size(const UINT32 comm, const TASKS_NODE *tasks_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, TASKS_NODE_SRVIPADDR(tasks_node), size);
    cmpi_encode_uint32_size(comm, TASKS_NODE_SRVPORT(tasks_node), size);
    cmpi_encode_uint32_size(comm, TASKS_NODE_TCID(tasks_node), size);
    cmpi_encode_uint32_size(comm, TASKS_NODE_COMM(tasks_node), size);
    cmpi_encode_uint32_size(comm, TASKS_NODE_SIZE(tasks_node), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_tasks_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASKS_NODE *tasks_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_tasks_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_tasks_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == tasks_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_tasks_node: tasks_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &TASKS_NODE_SRVIPADDR(tasks_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &TASKS_NODE_SRVPORT(tasks_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &TASKS_NODE_TCID(tasks_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &TASKS_NODE_COMM(tasks_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &TASKS_NODE_SIZE(tasks_node));

    return ((UINT32)0);
}
#endif

#if 1

UINT32 cmpi_encode_ctdnssv_node(const UINT32 comm, const CTDNSSV_NODE *ctdnssv_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == ctdnssv_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctdnssv_node: ctdnssv_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctdnssv_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctdnssv_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, CTDNSSV_NODE_TCID(ctdnssv_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CTDNSSV_NODE_IPADDR(ctdnssv_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CTDNSSV_NODE_PORT(ctdnssv_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_ctdnssv_node_size(const UINT32 comm, const CTDNSSV_NODE *ctdnssv_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, CTDNSSV_NODE_TCID(ctdnssv_node), size);
    cmpi_encode_uint32_size(comm, CTDNSSV_NODE_IPADDR(ctdnssv_node), size);
    cmpi_encode_uint32_size(comm, CTDNSSV_NODE_PORT(ctdnssv_node), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_ctdnssv_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CTDNSSV_NODE *ctdnssv_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == ctdnssv_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node: ctdnssv_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CTDNSSV_NODE_TCID(ctdnssv_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CTDNSSV_NODE_IPADDR(ctdnssv_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CTDNSSV_NODE_PORT(ctdnssv_node));

    return ((UINT32)0);
}


UINT32 cmpi_encode_ctdnssv_node_mgr(const UINT32 comm, const CTDNSSV_NODE_MGR *ctdnssv_node_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32           size;
    CLIST_DATA      *clist_data;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == ctdnssv_node_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctdnssv_node_mgr: ctdnssv_node_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctdnssv_node_mgr: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_ctdnssv_node_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    size = clist_size(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr));

    cmpi_encode_uint32(comm, size, out_buff, out_buff_max_len, position);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE *ctdnssv_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);
        cmpi_encode_ctdnssv_node(comm, ctdnssv_node, out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_ctdnssv_node_mgr_size(const UINT32 comm, const CTDNSSV_NODE_MGR *ctdnssv_node_mgr, UINT32 *size)
{
    CLIST_DATA      *clist_data;

    cmpi_encode_uint32_size(comm, (UINT32)0, size);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE *ctdnssv_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);
        cmpi_encode_ctdnssv_node_size(comm, ctdnssv_node, size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_ctdnssv_node_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    UINT32          size;
    UINT32          idx;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node_mgr: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node_mgr: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == ctdnssv_node_mgr )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node_mgr: ctdnssv_node_mgr is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &size);
    for(idx = 0; idx < size; idx ++)
    {
        CTDNSSV_NODE *ctdnssv_node;

        ctdnssv_node = ctdnssv_node_new();
        if(NULL_PTR == ctdnssv_node)
        {
            dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_ctdnssv_node_mgr: no memory\n");
            return ((UINT32)-1);
        }

        cmpi_decode_ctdnssv_node(comm, in_buff, in_buff_max_len, position, ctdnssv_node);
        clist_push_back(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), (void *)ctdnssv_node);
    }
    return ((UINT32)0);
}

#endif

#if 1

UINT32 cmpi_encode_cp2p_file(const UINT32 comm, const CP2P_FILE *cp2p_file, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cp2p_file )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cp2p_file: cp2p_file is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cp2p_file: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cp2p_file: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CP2P_FILE_SERVICE_NAME(cp2p_file), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CP2P_FILE_SRC_NAME(cp2p_file), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CP2P_FILE_DES_NAME(cp2p_file), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CP2P_FILE_SRC_SIZE(cp2p_file), out_buff, out_buff_max_len, position);
    cmpi_encode_cmd5_digest(comm, CP2P_FILE_SRC_MD5(cp2p_file), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CP2P_FILE_REPORT_TCID(cp2p_file), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cp2p_file_size(const UINT32 comm, const CP2P_FILE *cp2p_file, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CP2P_FILE_SERVICE_NAME(cp2p_file), size);
    cmpi_encode_cstring_size(comm, CP2P_FILE_SRC_NAME(cp2p_file), size);
    cmpi_encode_cstring_size(comm, CP2P_FILE_DES_NAME(cp2p_file), size);
    cmpi_encode_uint32_size(comm, CP2P_FILE_SRC_SIZE(cp2p_file), size);
    cmpi_encode_cmd5_digest_size(comm, CP2P_FILE_SRC_MD5(cp2p_file), size);
    cmpi_encode_uint32_size(comm, CP2P_FILE_REPORT_TCID(cp2p_file), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_cp2p_file(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CP2P_FILE *cp2p_file)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cp2p_file: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cp2p_file: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cp2p_file )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cp2p_file: cp2p_file is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CP2P_FILE_SERVICE_NAME(cp2p_file));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CP2P_FILE_SRC_NAME(cp2p_file));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CP2P_FILE_DES_NAME(cp2p_file));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CP2P_FILE_SRC_SIZE(cp2p_file)));
    cmpi_decode_cmd5_digest(comm, in_buff, in_buff_max_len, position, CP2P_FILE_SRC_MD5(cp2p_file));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &(CP2P_FILE_REPORT_TCID(cp2p_file)));

    return ((UINT32)0);
}

#endif

#if 1

UINT32 cmpi_encode_cp2p_cmd(const UINT32 comm, const CP2P_CMD *cp2p_cmd, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cp2p_cmd )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cp2p_cmd: cp2p_cmd is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cp2p_cmd: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cp2p_cmd: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_cstring(comm, CP2P_CMD_SERVICE_NAME(cp2p_cmd), out_buff, out_buff_max_len, position);
    cmpi_encode_cstring(comm, CP2P_CMD_COMMAND_LINE(cp2p_cmd), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cp2p_cmd_size(const UINT32 comm, const CP2P_CMD *cp2p_cmd, UINT32 *size)
{
    cmpi_encode_cstring_size(comm, CP2P_CMD_SERVICE_NAME(cp2p_cmd), size);
    cmpi_encode_cstring_size(comm, CP2P_CMD_COMMAND_LINE(cp2p_cmd), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_cp2p_cmd(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CP2P_CMD *cp2p_cmd)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cp2p_cmd: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cp2p_cmd: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cp2p_cmd )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cp2p_cmd: cp2p_cmd is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CP2P_CMD_SERVICE_NAME(cp2p_cmd));
    cmpi_decode_cstring(comm, in_buff, in_buff_max_len, position, CP2P_CMD_COMMAND_LINE(cp2p_cmd));

    return ((UINT32)0);
}

#endif

#if 1
UINT32 cmpi_encode_cxfsnp_inode(const UINT32 comm, const CXFSNP_INODE *cxfsnp_inode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cxfsnp_inode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_inode: cxfsnp_inode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_inode: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_inode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint16(comm, CXFSNP_INODE_DISK_NO(cxfsnp_inode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint16(comm, CXFSNP_INODE_BLOCK_NO(cxfsnp_inode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint16(comm, CXFSNP_INODE_PAGE_NO(cxfsnp_inode), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnp_inode_size(const UINT32 comm, const CXFSNP_INODE *cxfsnp_inode, UINT32 *size)
{
    cmpi_encode_uint16_size(comm, CXFSNP_INODE_DISK_NO(cxfsnp_inode), size);
    cmpi_encode_uint16_size(comm, CXFSNP_INODE_BLOCK_NO(cxfsnp_inode), size);
    cmpi_encode_uint16_size(comm, CXFSNP_INODE_PAGE_NO(cxfsnp_inode), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_cxfsnp_inode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_INODE *cxfsnp_inode)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_inode: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_inode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cxfsnp_inode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_inode: cxfsnp_inode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CXFSNP_INODE_DISK_NO(cxfsnp_inode)));
    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)));
    cmpi_decode_uint16(comm, in_buff, in_buff_max_len, position, &(CXFSNP_INODE_PAGE_NO(cxfsnp_inode)));

    return ((UINT32)0);
}


UINT32 cmpi_encode_cxfsnp_fnode(const UINT32 comm, const CXFSNP_FNODE *cxfsnp_fnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    uint32_t cxfsnp_inode_pos;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cxfsnp_fnode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_fnode: cxfsnp_fnode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_fnode: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_fnode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CXFSNP_FNODE_FILESZ(cxfsnp_fnode), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNP_FNODE_REPNUM(cxfsnp_fnode), out_buff, out_buff_max_len, position);

    for(cxfsnp_inode_pos = 0; cxfsnp_inode_pos < (CXFSNP_FNODE_REPNUM(cxfsnp_fnode)) && cxfsnp_inode_pos < CXFSNP_FILE_REPLICA_MAX_NUM; cxfsnp_inode_pos ++)
    {
        CXFSNP_INODE *cxfsnp_inode;

        cxfsnp_inode = (CXFSNP_INODE *)CXFSNP_FNODE_INODE(cxfsnp_fnode, cxfsnp_inode_pos);
        cmpi_encode_cxfsnp_inode(comm, cxfsnp_inode, out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnp_fnode_size(const UINT32 comm, const CXFSNP_FNODE *cxfsnp_fnode, UINT32 *size)
{
    uint32_t cxfsnp_inode_pos;

    cmpi_encode_uint32_t_size(comm, CXFSNP_FNODE_FILESZ(cxfsnp_fnode), size);
    cmpi_encode_uint32_t_size(comm, CXFSNP_FNODE_REPNUM(cxfsnp_fnode), size);

    for(cxfsnp_inode_pos = 0; cxfsnp_inode_pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode) && cxfsnp_inode_pos < CXFSNP_FILE_REPLICA_MAX_NUM; cxfsnp_inode_pos ++)
    {
        CXFSNP_INODE *cxfsnp_inode;

        cxfsnp_inode = (CXFSNP_INODE *)CXFSNP_FNODE_INODE(cxfsnp_fnode, cxfsnp_inode_pos);
        cmpi_encode_cxfsnp_inode_size(comm, cxfsnp_inode, size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_cxfsnp_fnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t file_size;
    uint32_t replica_num;
    uint32_t hash;

    uint32_t cxfsnp_inode_pos;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_fnode: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_fnode: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cxfsnp_fnode )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_fnode: cxfsnp_fnode is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(file_size));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(replica_num));
    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(hash));

    if(CXFSNP_FILE_REPLICA_MAX_NUM < (replica_num))
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT, "error:cmpi_decode_cxfsnp_fnode: replica num %ld overflow\n", replica_num);
        return ((UINT32)-1);
    }

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = (uint32_t)(file_size);
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = (uint32_t)(replica_num);

    for(cxfsnp_inode_pos = 0; cxfsnp_inode_pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode); cxfsnp_inode_pos ++)
    {
        CXFSNP_INODE *cxfsnp_inode;

        cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, cxfsnp_inode_pos);
        cmpi_decode_cxfsnp_inode(comm, in_buff, in_buff_max_len, position, cxfsnp_inode);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnp_key(const UINT32 comm, const CXFSNP_KEY *cxfsnp_key, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cxfsnp_key )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_key: cxfsnp_key is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_key: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_key: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint8(comm, CXFSNP_KEY_LEN(cxfsnp_key), out_buff, out_buff_max_len, position);
    cmpi_pack(CXFSNP_KEY_NAME(cxfsnp_key), CXFSNP_KEY_LEN(cxfsnp_key), CMPI_UCHAR, out_buff, out_buff_max_len, position, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnp_key_size(const UINT32 comm, const CXFSNP_KEY *cxfsnp_key, UINT32 *size)
{
    cmpi_encode_uint8_size(comm, CXFSNP_KEY_LEN(cxfsnp_key), size);
    cmpi_pack_size(CXFSNP_KEY_LEN(cxfsnp_key), CMPI_UCHAR, size,  comm);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cxfsnp_key(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_KEY *cxfsnp_key)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_key: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_key: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cxfsnp_key )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_key: cxfsnp_key is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint8(comm, in_buff, in_buff_max_len, position, &CXFSNP_KEY_LEN(cxfsnp_key));
    cmpi_unpack(in_buff, in_buff_max_len, position, CXFSNP_KEY_NAME(cxfsnp_key), CXFSNP_KEY_LEN(cxfsnp_key), CMPI_UCHAR, comm);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnpque_node(const UINT32 comm, const CXFSNPQUE_NODE *cxfsnpque_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cxfsnpque_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnpque_node: cxfsnpque_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnpque_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnpque_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CXFSNPQUE_NODE_PREV_POS(cxfsnpque_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNPQUE_NODE_NEXT_POS(cxfsnpque_node), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnpque_node_size(const UINT32 comm, const CXFSNPQUE_NODE *cxfsnpque_node, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CXFSNPQUE_NODE_PREV_POS(cxfsnpque_node), size);
    cmpi_encode_uint32_t_size(comm, CXFSNPQUE_NODE_NEXT_POS(cxfsnpque_node), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cxfsnpque_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNPQUE_NODE *cxfsnpque_node)
{
    uint32_t num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnpque_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnpque_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cxfsnpque_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnpque_node: cxfsnpque_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNPQUE_NODE_PREV_POS(cxfsnpque_node) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNPQUE_NODE_NEXT_POS(cxfsnpque_node)  = num;

    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnpdel_node(const UINT32 comm, const CXFSNPDEL_NODE *cxfsnpdel_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cxfsnpdel_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnpdel_node: cxfsnpdel_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnpdel_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnpdel_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CXFSNPDEL_NODE_PREV_POS(cxfsnpdel_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNPDEL_NODE_NEXT_POS(cxfsnpdel_node), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnpdel_node_size(const UINT32 comm, const CXFSNPDEL_NODE *cxfsnpdel_node, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CXFSNPDEL_NODE_PREV_POS(cxfsnpdel_node), size);
    cmpi_encode_uint32_t_size(comm, CXFSNPDEL_NODE_NEXT_POS(cxfsnpdel_node), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_cxfsnpdel_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNPDEL_NODE *cxfsnpdel_node)
{
    uint32_t num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnpdel_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnpdel_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cxfsnpdel_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnpdel_node: cxfsnpdel_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNPDEL_NODE_PREV_POS(cxfsnpdel_node) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNPDEL_NODE_NEXT_POS(cxfsnpdel_node)  = num;

    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnp_item(const UINT32 comm, const CXFSNP_ITEM *cxfsnp_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cxfsnp_item )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_item: cxfsnp_item is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_item: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cxfsnp_item: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32_t(comm, CXFSNP_ITEM_USED_FLAG(cxfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNP_ITEM_CREATE_TIME(cxfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNP_ITEM_KEY_OFFSET(cxfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32_t(comm, CXFSNP_ITEM_SECOND_HASH(cxfsnp_item), out_buff, out_buff_max_len, position);

    cmpi_encode_cxfsnpque_node(comm, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), out_buff, out_buff_max_len, position);
    cmpi_encode_cxfsnpdel_node(comm, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), out_buff, out_buff_max_len, position);

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cmpi_encode_uint32_t(comm, CXFSNP_DNODE_FILE_NUM(CXFSNP_ITEM_DNODE(cxfsnp_item)), out_buff, out_buff_max_len, position);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cmpi_encode_cxfsnp_fnode(comm, CXFSNP_ITEM_FNODE(cxfsnp_item), out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_cxfsnp_item_size(const UINT32 comm, const CXFSNP_ITEM *cxfsnp_item, UINT32 *size)
{
    cmpi_encode_uint32_t_size(comm, CXFSNP_ITEM_USED_FLAG(cxfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CXFSNP_ITEM_CREATE_TIME(cxfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CXFSNP_ITEM_KEY_OFFSET(cxfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), size);
    cmpi_encode_uint32_t_size(comm, CXFSNP_ITEM_SECOND_HASH(cxfsnp_item), size);

    cmpi_encode_cxfsnpque_node_size(comm, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), size);
    cmpi_encode_cxfsnpdel_node_size(comm, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), size);

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cmpi_encode_uint32_t_size(comm, CXFSNP_DNODE_FILE_NUM(CXFSNP_ITEM_DNODE(cxfsnp_item)), size);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cmpi_encode_cxfsnp_fnode_size(comm, CXFSNP_ITEM_FNODE(cxfsnp_item), size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_cxfsnp_item(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_ITEM *cxfsnp_item)
{
    uint32_t num;

#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_item: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_item: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cxfsnp_item )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cxfsnp_item: cxfsnp_item is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNP_ITEM_USED_FLAG(cxfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)  = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNP_ITEM_CREATE_TIME(cxfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNP_ITEM_KEY_OFFSET(cxfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item) = num;

    cmpi_decode_cxfsnpque_node(comm, in_buff, in_buff_max_len, position, CXFSNP_ITEM_QUE_NODE(cxfsnp_item));
    cmpi_decode_cxfsnpdel_node(comm, in_buff, in_buff_max_len, position, CXFSNP_ITEM_DEL_NODE(cxfsnp_item));

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &(num));
        CXFSNP_DNODE_FILE_NUM(CXFSNP_ITEM_DNODE(cxfsnp_item)) = num;
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cmpi_decode_cxfsnp_fnode(comm, in_buff, in_buff_max_len, position, CXFSNP_ITEM_FNODE(cxfsnp_item));
    }

    return ((UINT32)0);
}

#endif

#if 1
UINT32 cmpi_encode_cmon_node(const UINT32 comm, const CMON_NODE *cmon_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == cmon_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cmon_node: cmon_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == out_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cmon_node: out_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_encode_cmon_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_encode_uint32(comm, CMON_NODE_TCID(cmon_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CMON_NODE_IPADDR(cmon_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CMON_NODE_PORT(cmon_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CMON_NODE_MODI(cmon_node), out_buff, out_buff_max_len, position);
    cmpi_encode_uint32(comm, CMON_NODE_STATE(cmon_node), out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_cmon_node_size(const UINT32 comm, const CMON_NODE *cmon_node, UINT32 *size)
{
    cmpi_encode_uint32_size(comm, CMON_NODE_TCID(cmon_node), size);
    cmpi_encode_uint32_size(comm, CMON_NODE_IPADDR(cmon_node), size);
    cmpi_encode_uint32_size(comm, CMON_NODE_PORT(cmon_node), size);
    cmpi_encode_uint32_size(comm, CMON_NODE_MODI(cmon_node), size);
    cmpi_encode_uint32_size(comm, CMON_NODE_STATE(cmon_node), size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_cmon_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CMON_NODE *cmon_node)
{
#if ( SWITCH_ON == ENCODE_DEBUG_SWITCH )
    if ( NULL_PTR == in_buff )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cmon_node: in_buff is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == position )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cmon_node: position is null.\n");
        dbg_exit(MD_TBD, 0);
    }
    if ( NULL_PTR == cmon_node )
    {
        dbg_log(SEC_0035_CMPIE, 0)(LOGSTDOUT,"error:cmpi_decode_cmon_node: cmon_node is null.\n");
        dbg_exit(MD_TBD, 0);
    }
#endif /* ENCODE_DEBUG_SWITCH */

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CMON_NODE_TCID(cmon_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CMON_NODE_IPADDR(cmon_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CMON_NODE_PORT(cmon_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CMON_NODE_MODI(cmon_node));
    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &CMON_NODE_STATE(cmon_node));

    return ((UINT32)0);
}

#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

