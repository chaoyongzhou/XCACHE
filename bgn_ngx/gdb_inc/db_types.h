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

#ifndef _GNUPDATEDB_TYPES_H_
#define _GNUPDATEDB_TYPES_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#undef uint8_t
#undef uint16_t
#undef uint32_t
//#undef int8_t
//#undef int16_t
//#undef int32_t
#undef bool

#ifndef _UINT32_T_
#define _UINT32_T_
typedef unsigned int   uint32_t;
#endif/*_UINT32_T_*/

#ifndef _UINT16_T_
#define _UINT16_T_
typedef unsigned short   uint16_t;
#endif/*_UINT16_T_*/

#ifndef _UINT8_T_
#define _UINT8_T_
typedef unsigned char   uint8_t;
#endif/*_UINT8_T_*/

#ifndef _WORD_T_
#define _WORD_T_
typedef unsigned long  word_t;
#endif/*_WORD_T_*/


//typedef char  int8_t;
//typedef short int16_t;
//typedef int   int32_t;

typedef uint32_t offset_t;
#define OFFSETSIZE  32

//typedef uint8_t  bool;

typedef mode_t PmAccessMode;
#define PM_MODE_READ_WRITE      00100000
#define PM_MODE_READ_ONLY       00200000
#define PM_MODE_CREATED         00400000   /*add definition here:-)*/
#define PM_MODE_TEST            02000000
#define PM_MODE_ERROR           04000000

#define BTREE_ORDER      (32)

#if 0
#define BCOPY(src, des, len)    memcpy(des, src, len)
#define BSET(pstr, ch, len)     memset(pstr, ch, len)
#define BCMP(pstr1, pstr2, len) memcmp(pstr1, pstr2, len)

#define DMIN(a, b)      ((a) <= (b) ? (a) : (b))
#define DMAX(a, b)      ((a) <= (b) ? (b) : (a))

#define SWITCH_OFF       (0)
#define SWITCH_ON        (1)
#endif

#define COMPRESS_MODE    (SWITCH_OFF)
#define MEM_CHECK_SWITCH (SWITCH_ON)
#define HS_KEY_SWITCH    (SWITCH_ON)
#define HS_KV_SWITCH     (SWITCH_ON)

#undef true
#undef false
#define true             ((uint8_t) 1)
#define false            ((uint8_t) 0)

#endif /* _BTREE_LOCK_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
