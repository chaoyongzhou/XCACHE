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

#ifndef _CMPIC_INC
#define _CMPIC_INC

#define CMPI_COMM_NULL      ((UINT32)( 0))
#define CMPI_COMM_WORLD     ((UINT32)(91))
#define CMPI_MIN_SIZE       ((UINT32)( 1))

#define CMPI_ULONGLONG      ((UINT32)(8))
#define CMPI_ULONG          ((UINT32)(9))
#define CMPI_U32            ((UINT32)(7))
#define CMPI_USHORT         ((UINT32)(5))
#define CMPI_UCHAR          ((UINT32)(2))
#define CMPI_REAL           ((UINT32)(11))

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
#define CMPI_TOP_NETWORK    ((UINT32)(  0))
#define CMPI_ANY_NETWORK    ((UINT32)( -1))
#define CMPI_ERROR_NETWORK  ((UINT32)( -13))

#define CMPI_ANY_TCID       ((UINT32)( -1))
#define CMPI_ANY_MASK       ((UINT32)( -1))
#define CMPI_ANY_COMM       (CMPI_COMM_NULL)
#define CMPI_ANY_RANK       ((UINT32)( -2))
#define CMPI_ANY_MODI       ((UINT32)( -2))
#define CMPI_ANY_IPADDR     ((UINT32)( -3))
#define CMPI_ANY_SRVPORT    ((UINT32)( -4))
#define CMPI_ANY_TAG        ((UINT32)( -1))
#define CMPI_ANY_SOCKFD     ((int)   ( -5))

#define CMPI_ANY_DBG_TCID   ((UINT32)( -6))
#define CMPI_ANY_MON_TCID   ((UINT32)( -7))

#define CMPI_ERROR_TCID     ((UINT32)( -8))
#define CMPI_ERROR_MASK     ((UINT32)( -1))
#define CMPI_ERROR_COMM     (CMPI_COMM_NULL)
#define CMPI_ERROR_RANK     ((UINT32)( -9))
#define CMPI_ERROR_MODI     ((UINT32)( -10))
#define CMPI_ERROR_IPADDR   ((UINT32)(  0))
#define CMPI_ERROR_SRVPORT  ((UINT32)(  0))/*error server port*/
#define CMPI_ERROR_CLNTPORT ((UINT32)(  0))/*error client port*/
#define CMPI_ERROR_SOCKFD   ((int)   ( -1))
#define CMPI_ERROR_TAG      ((UINT32)(-12))

#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
                            /*    new setting    *//*old setting*/
#define CMPI_TOP_NETWORK    ((UINT32)(  0))/*((UINT32)(  0))*/
#define CMPI_ANY_NETWORK    ((UINT32)(0x0000FFFE))/*((UINT32)( -1))*/
#define CMPI_ERROR_NETWORK  ((UINT32)(0x0000FFF3))/*((UINT32)( -13))*/

#define CMPI_ANY_TCID       ((UINT32)(0xFFFFFFFF))/*((UINT32)( -1))*/
#define CMPI_ANY_MASK       ((UINT32)(0xFFFFFFFF))/*((UINT32)( -1))*/
#define CMPI_ANY_COMM       (CMPI_COMM_NULL)
#define CMPI_ANY_RANK       ((UINT32)(0x000000FE))/*((UINT32)( -2))*/
#define CMPI_ANY_MODI       ((UINT32)(0x0000FFFE))/*((UINT32)( -2))*/
#define CMPI_ANY_IPADDR     ((UINT32)(0xFFFFFFFD))/*((UINT32)( -3))*/
#define CMPI_ANY_SRVPORT    ((UINT32)(0xFFFFFFFC))/*((UINT32)( -4))*/
#define CMPI_ANY_TAG        ((UINT32)(0x000000FF)) /*((UINT32)( -1))*/
#define CMPI_ANY_SOCKFD     ((int)   ( -5))

#define CMPI_ANY_DBG_TCID   ((UINT32)(0xFFFFFFFA))/*((UINT32)( -6))*/
#define CMPI_ANY_MON_TCID   ((UINT32)(0xFFFFFFF9))/*((UINT32)( -7))*/

#define CMPI_ERROR_TCID     ((UINT32)(0xFFFFFFF8))/*((UINT32)( -8))*/
#define CMPI_ERROR_MASK     ((UINT32)(  1))
#define CMPI_ERROR_COMM     (CMPI_COMM_NULL)
#define CMPI_ERROR_RANK     ((UINT32)(0x000000F7))/*((UINT32)( -9))*/
#define CMPI_ERROR_MODI     ((UINT32)(0x0000FFF6))/*((UINT32)( -10))*/
#define CMPI_ERROR_IPADDR   ((UINT32)(  0))
#define CMPI_ERROR_SRVPORT  ((UINT32)(  0))/*error server port*/
#define CMPI_ERROR_CLNTPORT ((UINT32)(  0))/*error client port*/
#define CMPI_ERROR_SOCKFD   ((int)   ( -1))
#define CMPI_ERROR_TAG      ((UINT32)(0x000000F4))/*((UINT32)(-12))*/

#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/


#endif /*_CMPIC_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

