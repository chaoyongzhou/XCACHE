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

#ifndef _RAW_DATA_H_
#define _RAW_DATA_H_

#include "db_internal.h"
#include "mod.inc"

/**
* note:
*
* the raw file with not more than RAW_DATA_FILE_MAX_SIZE or  RAW_IDX_FILE_MAX_SIZE bytes will 
* be compressed and pushed into cdfs file (if CBGT_BASED_ON_HSDFS_SWITCH == SWITCH_ON)
* which accept up to RAW_CDFS_FILE_MAX_SIZE bytes
*
* one can set 
*     RAW_DATA_FILE_MAX_SIZE >> RAW_CDFS_FILE_MAX_SIZE 
*     RAW_IDX_FILE_MAX_SIZE  >> RAW_CDFS_FILE_MAX_SIZE 
* depending on compress algorithm
*
**/

#if (64 == WORDSIZE)
#define RAW_CDFS_FILE_MAX_SIZE  ((uint32_t)(63 * 1024 * 1024)) /*63M*/
#define RAW_DATA_FILE_MAX_SIZE  ((uint32_t)(63 * 1024 * 1024)) /*63M*/
#define RAW_IDX_FILE_MAX_SIZE   ((uint32_t)(63 * 1024 * 1024)) /*63M*/
#endif/*(64 == WORDSIZE)*/

#if (32 == WORDSIZE)
#define RAW_CDFS_FILE_MAX_SIZE  ((uint32_t)(1 * 1024 * 1024 - 4 * 1024))  /*1M - 4K*/
#define RAW_DATA_FILE_MAX_SIZE  ((uint32_t)(1 * 1024 * 1024)) /*63M*/
#define RAW_IDX_FILE_MAX_SIZE   ((uint32_t)(1 * 1024 * 1024)) /*63M*/
#endif/*(32 == WORDSIZE)*/

#define RAW_FILE_MIN_SIZE   ((uint32_t)(64 * 1024))        /*64K*/
#define RAW_FILE_HEAD_SIZE  ((uint32_t)(64))               /*64B*/

#define RAW_CDFS_FILE_REPLICA_NUM ((uint32_t) 1)

#define RAW_FILE_SUCC       ((uint8_t) 0)
#define RAW_FILE_FAIL       ((uint8_t) 1)

#define RAW_FILE_IS_RD      ((uint32_t) 1)
#define RAW_FILE_IS_RW      ((uint32_t) 3)

#define RAW_FILE_DEFAULT_CDFS_MODI ((UINT32) 0)


typedef struct
{
    uint32_t    max_size;
    uint32_t    head_size;
    uint32_t    cur_size;
    //uint32_t    cur_pos;
    uint8_t     dirty;
    uint8_t     buffer[0];
}RawData;

#define RAWDATA_IS_DIRTY(raw_data)    (((raw_data)->dirty) == 1)
#define RAWDATA_SET_DIRTY(raw_data)   ((raw_data)->dirty = 1)
#define RAWDATA_CLEAR_DIRTY(raw_data) ((raw_data)->dirty = 0)

typedef struct
{
    int         fd;
    int         open_flags;
    word_t      cdfs_md_id;
    uint8_t    *file_name;
    RawData    *raw_data;
}RawFile;

uint8_t   rawFileExist(const uint8_t *file_name, const word_t cdfs_md_id);
RawFile  *rawFileCreate(const uint8_t *file_name, const uint32_t file_size, const word_t cdfs_md_id);
RawFile  *rawFileOpen(const uint8_t *file_name, const int flags, const uint32_t file_size, const word_t cdfs_md_id);
uint8_t   rawFileClose(RawFile *raw_file);
uint8_t   rawFileLoad(RawFile *raw_file);
uint8_t   rawFileFlush(RawFile *raw_file);
uint32_t  rawFileMaxSize(const RawFile *raw_file);
uint32_t  rawFileCurSize(const RawFile *raw_file);
uint32_t  rawFileRoomSize(const RawFile *raw_file);
uint8_t   rawFileIsFull(const RawFile *raw_file, const uint32_t min_size);
uint8_t   rawFileAppend8s(RawFile *raw_file, const uint8_t *data, const uint32_t len, uint32_t *offset);
uint8_t   rawFileAppend8slen(RawFile *raw_file, const uint8_t *data, const uint32_t len, uint32_t *offset);
uint8_t   rawFileUpdate8s(RawFile *raw_file, const uint8_t *data, const uint32_t len, const uint32_t offset);
uint8_t   rawFileUpdate8slen(RawFile *raw_file, const uint8_t *data, const uint32_t len, const uint32_t offset);
uint8_t   rawFileRead8s(const RawFile *raw_file, uint8_t *data, const uint32_t max_len, uint32_t *len, const uint32_t offset);
uint8_t   rawFileRead8slen(const RawFile *raw_file, uint8_t *data, const uint32_t max_len, uint32_t *len, const uint32_t offset);
uint8_t   rawFileRead8(const RawFile *raw_file, uint8_t *data, const uint32_t offset);
uint8_t   rawFileRead16(const RawFile *raw_file, uint16_t *data, const uint32_t offset);
uint8_t   rawFileRead32(const RawFile *raw_file, uint32_t *data, const uint32_t offset);
uint8_t   rawFileWrite8(const RawFile *raw_file, const uint8_t data, const uint32_t offset);
uint8_t   rawFileWrite16(const RawFile *raw_file, const uint16_t data, const uint32_t offset);
uint8_t   rawFileWrite32(const RawFile *raw_file, const uint32_t data, const uint32_t offset);

RawFile  *rawFileNew(const uint8_t *file_name, const int fd, const int flags, const uint32_t file_size, const word_t cdfs_md_id);
uint8_t   rawFileFree(RawFile *raw_file);
uint8_t   rawFileUnMake(RawFile *raw_file);
uint8_t   rawFileInit(RawFile *raw_file, const uint8_t *file_name, const int fd, const int flags, const uint32_t file_size, const word_t cdfs_md_id);
uint8_t   rawFileReset(RawFile *raw_file);
uint8_t   rawFileClean(RawFile *raw_file);

size_t    rawFileRead(RawFile *raw_file, const offset_t offset, void *des, size_t size, size_t nmemb, const word_t location);
size_t    rawFileWrite(RawFile *raw_file, const offset_t offset, const void *src, size_t size, size_t nmemb, const word_t location);
size_t    rawFilePuts(RawFile *raw_file, const offset_t offset, const char *src);
uint8_t   rawFileSeek(RawFile *raw_file, long offset, int whence);
//uint32_t  rawFileTell(const RawFile *raw_file);

RawData  *rawDataNew(const uint32_t max_size, const uint32_t head_size);
uint8_t   rawDataFree(RawData *raw_data);
uint8_t   rawDataUnMake(RawData *raw_data);
uint8_t   rawDataInit(RawData *raw_data, const uint32_t max_size, const uint32_t head_size);
uint8_t   rawDataClean(RawData *raw_data);
uint8_t   rawDataReset(RawData *raw_data);
uint8_t   rawDataCompress(const RawData *raw_data, uint8_t *des, word_t *des_len);
uint8_t   rawDataUnCompress(RawData *raw_data, const uint8_t *src, const word_t src_len);
uint8_t   rawDataLoad(RawData *raw_data, const RawFile *raw_file);
uint8_t   rawDataFlush(RawData *raw_data, const RawFile *raw_file);
uint32_t  rawDataMaxSize(const RawData *raw_data);
uint32_t  rawDataCurSize(const RawData *raw_data);
uint32_t  rawDataRoomSize(const RawData *raw_data);
uint8_t   rawDataIsFull(const RawData *raw_data, const uint32_t min_size);
uint8_t   rawDataPut8(RawData *raw_data, const offset_t offset, const uint8_t data);
uint8_t   rawDataPut16(RawData *raw_data, const offset_t offset, const uint16_t data);
uint8_t   rawDataPut32(RawData *raw_data, const offset_t offset, const uint32_t data);
uint8_t   rawDataPut8s(RawData *raw_data, const offset_t offset, const uint8_t *data, const uint32_t len);
uint8_t   rawDataPut8slen(RawData *raw_data, const offset_t offset, const uint8_t *data, const uint32_t len);
uint8_t   rawDataUpdate8s(RawData *raw_data, const uint32_t offset, const uint8_t *data, const uint32_t len);
uint8_t   rawDataUpdate8slen(RawData *raw_data, const uint32_t offset, const uint8_t *data, const uint32_t len);
uint8_t   rawDataGet8(const RawData *raw_data, const uint32_t offset, uint8_t *data);
uint8_t   rawDataGet16(const RawData *raw_data, const uint32_t offset, uint16_t *data);
uint8_t   rawDataGet32(const RawData *raw_data, const uint32_t offset, uint32_t *data);
uint8_t   rawDataGet8s(const RawData *raw_data, const uint32_t offset, uint8_t *data, const uint32_t max_len, uint32_t *len);
uint8_t   rawDataGet8slen(const RawData *raw_data, const uint32_t offset, uint8_t *data, const uint32_t max_len, uint32_t *len);

size_t    rawDataRead(RawData *raw_data, const offset_t offset, void *des, size_t size, size_t nmemb);
size_t    rawDataWrite(RawData *raw_data, const offset_t offset, const void *src, size_t size, size_t nmemb);
size_t    rawDataPuts(RawData *raw_data, const offset_t offset,  const char *src);
uint8_t   rawDataSeek(RawData *raw_data, long offset, int whence);
//uint32_t  rawDataTell(const RawData *raw_data);

#endif /* _RAW_DATA_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
