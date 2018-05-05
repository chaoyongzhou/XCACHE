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


#ifndef _GNUPDATEDB_INTERNAL_H_
#define _GNUPDATEDB_INTERNAL_H_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <string.h>
#else
# ifdef HAVE_STRING_H
#  include <string.h>
# else
#  include <strings.h>
# endif
#endif

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#ifdef WITH_LEAKBUG
# include <leakbug.h>
# define LB_REGISTER(ptr, dataSize) \
    lbRegister((ptr), (dataSize), __FILE__, __LINE__, LEAKBUG_DEBUG_LEVEL)
# define LB_REGISTER_ARRAY(ptr, dataSize, numElements) \
    lbRegisterArray((void **)(ptr), (dataSize), (numElements), \
                    __FILE__, __LINE__, LEAKBUG_DEBUG_LEVEL)
#else
# define LB_REGISTER(ptr, dataSize)
# define LB_REGISTER_ARRAY(ptr, dataSize, numElements)
#endif

#ifdef ENABLE_NLS
# include <libintl.h>
# undef _
# define _(String) dgettext(PACKAGE, String)
# ifdef gettext_noop
#  define N_(String) gettext_noop(String)
# else
#  define N_(String) (String)
# endif
#else
# define textdomain(String) (String)
# define gettext(String) (String)
# define dgettext(Domain,Message) (Message)
# define dcgettext(Domain,Message,Type) (Message)
# define bindtextdomain(Domain,Directory) (Domain)
# define _(String) (String)
# define N_(String) (String)
#endif

#define MEM_CHECK(tmp) do{\
    if ((tmp) == NULL) { \
        sys_log(LOGSTDERR, "Error: Out of memory in %s, line %d\n", __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    }\
}while(0)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#include "btree.h"
#include "btree_header.h"
#include "btree_lock.h"
#include "btree_node.h"

#include "raw_data.h"
#include "keyvalue.h"
#include "list_base.h"
#include "poslist.h"

#include "db.h"
#include "db_blocks.h"
#include "db_blocklist.h"
#include "db_cache.h"
#include "db_header.h"
#include "db_utils.h"

#include "type.h"
#include "mm.h"
#include "log.h"

#include "mod.inc"
#include "mod.h"

#include "cdfs.h"
#include "cmap.h"

#define cxReturnValueIf(cond, retval) do{if((cond)) return (retval);}while(0)

#define cxReturnValueUnless(cond, retval) do{if(!(cond)) return (retval);}while(0)

#define cxReturnUnless(cond) do{if(!(cond)) return;}while(0)

#define cxGotoUnless(cond, lable) do{if(!(cond)) goto lable;}while(0)

#define cxExitUnless(cond) do{\
    if (!(cond)) { \
        sys_log(LOGSTDOUT, "Error: assert failed at %s:%d\n", __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    }\
}while(0)

#if (__BYTE_ORDER == __BIG_ENDIAN)
#define gdb_ntoh_uint32(x)       (x)
#define gdb_hton_uint32(x)       (x)

#define gdb_ntoh_uint16(x)       (x)
#define gdb_hton_uint16(x)       (x)

#define gdb_ntoh_offset(x)       (x)
#define gdb_hton_offset(x)       (x)

#endif/*(__BYTE_ORDER == __BIG_ENDIAN)*/

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define gdb_ntoh_uint32(x)       __bswap_32(x)
#define gdb_hton_uint32(x)       __bswap_32(x)

#define gdb_ntoh_uint64(x)       __bswap_64(x)
#define gdb_hton_uint64(x)       __bswap_64(x)

#define gdb_ntoh_uint16(x)       __bswap_16(x)
#define gdb_hton_uint16(x)       __bswap_16(x)

#if (32 == OFFSETSIZE)
#define gdb_ntoh_offset(x)       __bswap_32(x)
#define gdb_hton_offset(x)       __bswap_32(x)
#endif/*(32 == OFFSETSIZE)*/


#if (64 == OFFSETSIZE)
#define gdb_ntoh_offset(x)       __bswap_64(x)
#define gdb_hton_offset(x)       __bswap_64(x)
#endif/*(64 == OFFSETSIZE)*/

#if (32 == WORDSIZE)
#define gdb_ntoh_word(x)         __bswap_32(x)
#define gdb_hton_word(x)         __bswap_32(x)
#define gdb_ntoh_time(x)         __bswap_32(x)
#define gdb_hton_time(x)         __bswap_32(x)
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
#define gdb_ntoh_word(x)         __bswap_64(x)
#define gdb_hton_word(x)         __bswap_64(x)
#define gdb_ntoh_time(x)         __bswap_64(x)
#define gdb_hton_time(x)         __bswap_64(x)
#endif/*(64 == WORDSIZE)*/

#endif/*(__BYTE_ORDER == __LITTLE_ENDIAN)*/

#define GDB_TRUE                (EC_TRUE)
#define GDB_FALSE               (EC_FALSE)

#define TABLE_PATH_LAYOUT_DIR0_NBITS    ( 8)
#define TABLE_PATH_LAYOUT_DIR1_NBITS    ( 8)
#define TABLE_PATH_LAYOUT_DIR2_NBITS    ( 8)
#define TABLE_PATH_LAYOUT_DIR3_NBITS    ( 8)

#define TABLE_PATH_LAYOUT_DIR0_ABITS    (24) /*bit alignment*/
#define TABLE_PATH_LAYOUT_DIR1_ABITS    (16) /*bit alignment*/
#define TABLE_PATH_LAYOUT_DIR2_ABITS    ( 8) /*bit alignment*/
#define TABLE_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/

#define TABLE_PATH_LAYOUT_DIR0_MASK     (((UINT32)(UINT32_ONE << TABLE_PATH_LAYOUT_DIR0_NBITS)) - 1)
#define TABLE_PATH_LAYOUT_DIR1_MASK     (((UINT32)(UINT32_ONE << TABLE_PATH_LAYOUT_DIR1_NBITS)) - 1)
#define TABLE_PATH_LAYOUT_DIR2_MASK     (((UINT32)(UINT32_ONE << TABLE_PATH_LAYOUT_DIR2_NBITS)) - 1)
#define TABLE_PATH_LAYOUT_DIR3_MASK     (((UINT32)(UINT32_ONE << TABLE_PATH_LAYOUT_DIR3_NBITS)) - 1)

#define TABLE_PATH_LAYOUT_DIR0_NO(path_id)     (((path_id) >> TABLE_PATH_LAYOUT_DIR0_ABITS) & TABLE_PATH_LAYOUT_DIR0_MASK)
#define TABLE_PATH_LAYOUT_DIR1_NO(path_id)     (((path_id) >> TABLE_PATH_LAYOUT_DIR1_ABITS) & TABLE_PATH_LAYOUT_DIR1_MASK)
#define TABLE_PATH_LAYOUT_DIR2_NO(path_id)     (((path_id) >> TABLE_PATH_LAYOUT_DIR2_ABITS) & TABLE_PATH_LAYOUT_DIR2_MASK)
#define TABLE_PATH_LAYOUT_DIR3_NO(path_id)     (((path_id) >> TABLE_PATH_LAYOUT_DIR3_ABITS) & TABLE_PATH_LAYOUT_DIR3_MASK)

#endif /* _GNUPDATEDB_INTERNAL_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
