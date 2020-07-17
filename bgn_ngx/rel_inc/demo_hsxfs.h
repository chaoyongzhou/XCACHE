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

#ifndef _DEMO_HSXFS_H
#define _DEMO_HSXFS_H

#include "type.h"
#include "cbytes.h"

#define CXFS_TEST_SCENARIO_1K_TO_16K (1)
#define CXFS_TEST_SCENARIO_1K_TO_32K (2)
#define CXFS_TEST_SCENARIO_4K_TO_1M  (3)
#define CXFS_TEST_SCENARIO_4K_TO_4M  (4)

#if (32 == WORDSIZE)
/*scenario choice*/
#define CXFS_TEST_SCENARIO_CHOICE    (CXFS_TEST_SCENARIO_1K_TO_16K)

/*common definition*/
#define CXFS_NP_CACHED_MAX_NUM       ((UINT32)   8)
#define CXFS_NP_MIN_NUM              ((UINT32)   1)/*xxx*/
#define CXFS_MAX_FILE_NUM_PER_LOOP   ((UINT32)  64)/*xxx num of files handled per loop(= CXFSNP_DIR_FILE_MAX_NUM)*/

#if (CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 16;

#define CXFS_TEST_WRITE_MAX_FILES  4
#define CXFS_TEST_READ_MAX_FILES   4
#define CXFS_TEST_LOOP_MAX_TIMES   128
#endif/*(CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_1K_TO_32K == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 17;

#define CXFS_TEST_WRITE_MAX_FILES  4
#define CXFS_TEST_READ_MAX_FILES   4
#define CXFS_TEST_LOOP_MAX_TIMES   128
#endif/*(CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_4K_TO_1M == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 9;

#define CXFS_TEST_WRITE_MAX_FILES   4/*xxx*/
#define CXFS_TEST_READ_MAX_FILES    4/*xxx*/
#define CXFS_TEST_LOOP_MAX_TIMES   16/*xxx*/
#endif/*(CXFS_TEST_SCENARIO_4K_TO_1M == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_4K_TO_4M == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 11;

#define CXFS_TEST_WRITE_MAX_FILES 128
#define CXFS_TEST_READ_MAX_FILES  128
#define CXFS_TEST_LOOP_MAX_TIMES  256
#endif/*(CXFS_TEST_SCENARIO_4K_TO_4M == CXFS_TEST_SCENARIO_CHOICE)*/
#endif/*(32 == WORDSIZE)*/


#if (64 == WORDSIZE)
/*scenario choice*/
//#define CXFS_TEST_SCENARIO_CHOICE    (CXFS_TEST_SCENARIO_4K_TO_4M)
//#define CXFS_TEST_SCENARIO_CHOICE    (CXFS_TEST_SCENARIO_4K_TO_1M)
#define CXFS_TEST_SCENARIO_CHOICE    (CXFS_TEST_SCENARIO_1K_TO_16K)

/*common definition*/
#define CXFS_NP_CACHED_MAX_NUM       ((UINT32)  16)/*num of hot np cached in memory*/
#define CXFS_NP_MIN_NUM              ((UINT32)   1)/*xxx*/
#define CXFS_MAX_FILE_NUM_PER_LOOP   ((UINT32)1024)/*xxx num of files handled per loop(= CXFSNP_DIR_FILE_MAX_NUM)*/

#if (CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 16;

#define CXFS_TEST_WRITE_MAX_FILES 128
#define CXFS_TEST_READ_MAX_FILES  128
#define CXFS_TEST_LOOP_MAX_TIMES  512000000
#endif/*(CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_1K_TO_32K == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 17;

#define CXFS_TEST_WRITE_MAX_FILES 128
#define CXFS_TEST_READ_MAX_FILES  128
#define CXFS_TEST_LOOP_MAX_TIMES  512000000
#endif/*(CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_4K_TO_1M == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 9;

#define CXFS_TEST_WRITE_MAX_FILES  128/*xxx*/
#define CXFS_TEST_READ_MAX_FILES   128/*xxx*/
#define CXFS_TEST_LOOP_MAX_TIMES   128000000/*xxx*/
#endif/*(CXFS_TEST_SCENARIO_4K_TO_1M == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_4K_TO_4M == CXFS_TEST_SCENARIO_CHOICE)
static UINT32 g_cxfs_cbytes_used_num = 11;

#define CXFS_TEST_WRITE_MAX_FILES 128
#define CXFS_TEST_READ_MAX_FILES  128
#define CXFS_TEST_LOOP_MAX_TIMES  256000000
#endif/*(CXFS_TEST_SCENARIO_4K_TO_4M == CXFS_TEST_SCENARIO_CHOICE)*/
#endif/*(64 == WORDSIZE)*/

typedef struct
{
    char  *file_name;
    UINT32 file_size;
}DEMO_CXFS_FILE_CFG;

//#define DATA_FILES_ROOT_DIR "/home/ezhocha"
#define DATA_FILES_ROOT_DIR "/tmp"
static   DEMO_CXFS_FILE_CFG g_cxfs_file_cfg_tbl[] = {
#if (CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)
        {(char *)DATA_FILES_ROOT_DIR"/data_files/1K.dat",     1 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/2K.dat",     2 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/3K.dat",     3 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/4K.dat",     4 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/5K.dat",     5 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/6K.dat",     6 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/7K.dat",     7 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/8K.dat",     8 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/9K.dat",     9 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/10K.dat",   10 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/11K.dat",   11 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/12K.dat",   12 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/13K.dat",   13 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/14K.dat",   14 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/15K.dat",   15 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/16K.dat",   16 * 1024},
#endif/*(CXFS_TEST_SCENARIO_1K_TO_16K == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_1K_TO_32K == CXFS_TEST_SCENARIO_CHOICE)
        {(char *)DATA_FILES_ROOT_DIR"/data_files/1K.dat",     1 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/2K.dat",     2 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/3K.dat",     3 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/4K.dat",     4 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/5K.dat",     5 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/6K.dat",     6 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/7K.dat",     7 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/8K.dat",     8 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/9K.dat",     9 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/10K.dat",   10 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/11K.dat",   11 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/12K.dat",   12 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/13K.dat",   13 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/14K.dat",   14 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/15K.dat",   15 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/16K.dat",   16 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/32K.dat",   32 * 1024},
#endif/*(CXFS_TEST_SCENARIO_1K_TO_32K == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_4K_TO_1M == CXFS_TEST_SCENARIO_CHOICE)
        {(char *)DATA_FILES_ROOT_DIR"/data_files/4K.dat",     4 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/8K.dat",     8 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/16K.dat",   16 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/32K.dat",   32 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/64K.dat",   64 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/128K.dat", 128 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/256K.dat", 256 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/512K.dat", 512 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/1M.dat",     1 * 1024 * 1024},
#endif/*(CXFS_TEST_SCENARIO_4K_TO_1M == CXFS_TEST_SCENARIO_CHOICE)*/

#if (CXFS_TEST_SCENARIO_4K_TO_4M == CXFS_TEST_SCENARIO_CHOICE)
        {(char *)DATA_FILES_ROOT_DIR"/data_files/4K.dat",     4 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/8K.dat",     8 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/16K.dat",   16 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/32K.dat",   32 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/64K.dat",   64 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/128K.dat", 128 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/256K.dat", 256 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/512K.dat", 512 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/1M.dat",     1 * 1024 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/2M.dat",     2 * 1024 * 1024},
        {(char *)DATA_FILES_ROOT_DIR"/data_files/4M.dat",     4 * 1024 * 1024},
#endif/*(CXFS_TEST_SCENARIO_4K_TO_4M == CXFS_TEST_SCENARIO_CHOICE)*/
};


typedef struct
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 modi;

    const char *home_dir;
}DEMO_HSXFS_ARG;

typedef struct
{
    CSTRING     *xfs_sata_path;
    CSTRING     *xfs_ssd_path;

    uint32_t     xfs_retrive_flag:1;
    uint32_t     rsvd01          :31;
    uint32_t     rsvd02;
}DEMO_HSXFS_CFG;

#endif /*_DEMO_HSXFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

