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

#include "db_internal.h"
#include <libgen.h>
#include "zlib.h"
#include <errno.h>

STATIC_CAST static uint8_t __mkdir(const char *dir_name)
{
    char *pstr;

    int   len;
    int   pos;

    if(0 == access(dir_name, F_OK))/*exist*/
    {
        return 1;
    }

    pstr = strdup(dir_name);
    if(NULL == pstr)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:__mkdir: strdup failed\n");
        return 0;
    }

    len  = strlen(pstr);

    for(pos = 1; pos < len; pos ++)
    {
        int loop;

        if('/' != pstr[ pos ])
        {
            continue;
        }

        pstr[ pos ] = '\0';

        for(loop = 0; loop < 3 && 0 != access(pstr, F_OK) && 0 != mkdir(pstr, 0755); loop ++)/*try 3 times*/
        {
            /*do nothing*/
        }

        if(3 <= loop)
        {
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:__mkdir: create dir %s failed\n", pstr);
            pstr[ pos ] = '/';

            free(pstr);
            return 0;
        }
        pstr[ pos ] = '/';
    }

    if(0 != access(dir_name, F_OK) && 0 != mkdir(dir_name, 0755))
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:__mkdir: create dir %s failed\n", dir_name);
        free(pstr);
        return 0;
    }

    free(pstr);
    return 1;
}

STATIC_CAST static uint8_t *__dupFileName(const uint8_t *root_path)
{
    uint8_t *file_name;
    MEM_CHECK(file_name = (uint8_t *)SAFE_MALLOC(strlen((char *)root_path) + 1, LOC_RAW_0001));
    sprintf((char *)file_name, "%s", (char *)root_path);
    return (file_name);
}

STATIC_CAST static uint8_t __mkbasedir(const char *file_name)
{
    char *dir_name;
    uint8_t ret;

    dir_name = strdup(file_name);
    dir_name = dirname(dir_name);
    ret = __mkdir(dir_name);
    free(dir_name);
    return ret;
}

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t  rawFileExist(const uint8_t *file_name, const word_t cdfs_md_id)
{
    MEM_CHECK(file_name);
    if(0 == access((char *)file_name, F_OK))
    {
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t  rawFileExist(const uint8_t *file_name, const word_t cdfs_md_id)
{
    CSTRING *fname_cstr;
    MEM_CHECK(file_name);

    fname_cstr = cstring_new(file_name, LOC_RAW_0002);
    if(NULL_PTR == fname_cstr)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileExist: new file name string failed\n");
        return RAW_FILE_FAIL;
    }

    if(EC_FALSE == cdfs_exists_npp(cdfs_md_id, fname_cstr))
    {
        cstring_free(fname_cstr);
        return RAW_FILE_FAIL;
    }

    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
RawFile *rawFileCreate(const uint8_t *file_name, const uint32_t file_size, const word_t cdfs_md_id)
{
    RawFile * raw_file;
    int fd;

    MEM_CHECK(file_name);
#if 0
    if(!__mkbasedir((char *)file_name))
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileCreate: mkbasedir of file %s failed\n", (char *)file_name);
        return NULL;
    }
#endif
    fd = c_open((char *)file_name, O_RDWR | O_CREAT, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT,"error:rawFileCreate: create %s failed\n", file_name);
        return NULL;
    }

    raw_file = rawFileNew(file_name, fd, O_RDWR | O_CREAT, file_size, cdfs_md_id);
    if(NULL == raw_file)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileCreate: new raw file failed\n");
        close(fd);
        return NULL;
    }

    return raw_file;
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
RawFile *rawFileCreate(const uint8_t *file_name, const uint32_t file_size, const word_t cdfs_md_id)
{
    RawFile * raw_file;
    CSTRING *fname_cstr;

    MEM_CHECK(file_name);

    fname_cstr = cstring_new(file_name, LOC_RAW_0003);
    if(NULL_PTR == fname_cstr)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileCreate: new file name string failed\n");
        return NULL;
    }

    raw_file = rawFileNew(file_name, -1, O_RDWR | O_CREAT, file_size, cdfs_md_id);
    if(NULL == raw_file)
    {
        cstring_free(fname_cstr);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileCreate: new raw file failed\n");
        return NULL;
    }

    /**
    *
    * the raw file with not more than file_size bytes will be compressed
    * and pushed into cdfs file which accept up to RAW_CDFS_FILE_MAX_SIZE bytes
    *
    * one can set file_size >> RAW_CDFS_FILE_MAX_SIZE depending on compress algorithm
    *
    **/
    if(EC_FALSE == cdfs_truncate(cdfs_md_id, fname_cstr, RAW_CDFS_FILE_MAX_SIZE, RAW_CDFS_FILE_REPLICA_NUM))
    {
        cstring_free(fname_cstr);
        rawFileFree(raw_file);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileCreate: truncate %s with size %d and replica %d failed\n",
                          (char *)file_name, RAW_CDFS_FILE_MAX_SIZE, RAW_CDFS_FILE_REPLICA_NUM);
        return NULL;
    }

    cstring_free(fname_cstr);
    return raw_file;
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
RawFile * rawFileOpen(const uint8_t *file_name, const int flags, const uint32_t file_size, const word_t cdfs_md_id)
{
    MEM_CHECK(file_name);

    if(flags & O_RDWR)
    {
        RawFile * raw_file;
        int fd;

        fd = c_open((char *)file_name, O_RDWR, 0666);
        if(-1 != fd)
        {
            raw_file = rawFileNew(file_name, fd, O_RDWR, file_size, cdfs_md_id);
            if(NULL == raw_file)
            {
                dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileOpen: new raw file failed\n");
                close(fd);
                return NULL;
            }
            if(RAW_FILE_SUCC != rawFileLoad(raw_file))
            {
                dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileOpen: load %s failed\n", (char *)file_name);
                close(raw_file->fd);
                raw_file->fd = -1;

                rawFileFree(raw_file);
                return NULL;
            }

            return raw_file;
        }
    }

    if(flags & O_CREAT)
    {
        return rawFileCreate(file_name, file_size, cdfs_md_id);
    }

    //dbg_log(SEC_0132_RAW, 1)(LOGSTDOUT, "warn:rawFileOpen: open %s failed which neither exist nor need to create\n", (char *)file_name);
    return NULL;
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
RawFile * rawFileOpen(const uint8_t *file_name, const int flags, const uint32_t file_size, const word_t cdfs_md_id)
{
    MEM_CHECK(file_name);

    if(flags & O_RDWR)
    {
        RawFile   * raw_file;
#if 0
        CBYTES    * cbytes;
        CSTRING   * fname_cstr;
#endif
        raw_file = rawFileNew(file_name, -1, O_RDWR, file_size, cdfs_md_id);
        if(NULL == raw_file)
        {
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileOpen: new raw file failed\n");
            return NULL;
        }

        if(RAW_FILE_SUCC != rawFileLoad(raw_file))
        {
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileOpen: load %s failed\n", (char *)file_name);
            raw_file->fd = -1;
            rawFileFree(raw_file);
            return NULL;
        }
        return raw_file;
    }

    if(flags & O_CREAT)
    {
        return rawFileCreate(file_name, file_size, cdfs_md_id);
    }

    return NULL;
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

uint8_t   rawFileLoad(RawFile *raw_file)
{
    MEM_CHECK(raw_file);
    return rawDataLoad(raw_file->raw_data, raw_file);
}

uint8_t   rawFileFlush(RawFile *raw_file)
{
    MEM_CHECK(raw_file);
    dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawFileFlush: file %s (fd %d, flags %d) is %s\n",
                        (char *)raw_file->file_name, raw_file->fd, raw_file->open_flags,
                        RAWDATA_IS_DIRTY(raw_file->raw_data) ? "dirty" : "not dirty"
                        );
    return rawDataFlush(raw_file->raw_data, raw_file);
}

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t   rawFileClose(RawFile *raw_file)
{
    MEM_CHECK(raw_file);

    if(-1 != raw_file->fd)
    {
        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawFileClose: close file %s\n", raw_file->file_name);
        ASSERT(0 == close(raw_file->fd));
        raw_file->fd = -1;
    }

    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t   rawFileClose(RawFile *raw_file)
{
    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

uint32_t  rawFileMaxSize(const RawFile *raw_file)
{
    return rawDataMaxSize(raw_file->raw_data);
}

uint32_t  rawFileCurSize(const RawFile *raw_file)
{
    return rawDataCurSize(raw_file->raw_data);
}

uint32_t  rawFileRoomSize(const RawFile *raw_file)
{
    return rawDataRoomSize(raw_file->raw_data);
}

uint8_t   rawFileIsFull(const RawFile *raw_file, const uint32_t min_size)
{
    return rawDataIsFull(raw_file->raw_data, min_size);
}

uint8_t   rawFileAppend8s(RawFile *raw_file, const uint8_t *data, const uint32_t len, uint32_t *offset)
{
    MEM_CHECK(raw_file);
    //MEM_CHECK(offset);
    (*offset) = raw_file->raw_data->cur_size;
    return rawDataPut8s(raw_file->raw_data, (*offset), data, len);
}

uint8_t   rawFileAppend8slen(RawFile *raw_file, const uint8_t *data, const uint32_t len, uint32_t *offset)
{
    //MEM_CHECK(raw_file);
    //MEM_CHECK(offset);
    (*offset) = raw_file->raw_data->cur_size;
    return rawDataPut8slen(raw_file->raw_data, (*offset), data, len);
}

uint8_t   rawFileUpdate8s(RawFile *raw_file, const uint8_t *data, const uint32_t len, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    //MEM_CHECK(offset);

    return rawDataUpdate8s(raw_file->raw_data, offset, data, len);
}

uint8_t   rawFileUpdate8slen(RawFile *raw_file, const uint8_t *data, const uint32_t len, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    //MEM_CHECK(offset);
    return rawDataUpdate8slen(raw_file->raw_data, offset, data, len);
}

uint8_t   rawFileRead8s(const RawFile *raw_file, uint8_t *data, const uint32_t max_len, uint32_t *len, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataGet8s(raw_file->raw_data, offset, data, max_len, len);
}

uint8_t   rawFileRead8slen(const RawFile *raw_file, uint8_t *data, const uint32_t max_len, uint32_t *len, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataGet8slen(raw_file->raw_data, offset, data, max_len, len);
}

uint8_t   rawFileRead8(const RawFile *raw_file, uint8_t *data, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataGet8(raw_file->raw_data, offset, data);
}

uint8_t   rawFileRead16(const RawFile *raw_file, uint16_t *data, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataGet16(raw_file->raw_data, offset, data);
}

uint8_t   rawFileRead32(const RawFile *raw_file, uint32_t *data, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataGet32(raw_file->raw_data, offset, data);
}

uint8_t   rawFileWrite8(const RawFile *raw_file, const uint8_t data, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataPut8(raw_file->raw_data, offset, data);
}

uint8_t   rawFileWrite16(const RawFile *raw_file, const uint16_t data, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataPut16(raw_file->raw_data, offset, data);
}

uint8_t   rawFileWrite32(const RawFile *raw_file, const uint32_t data, const uint32_t offset)
{
    MEM_CHECK(raw_file);
    return rawDataPut32(raw_file->raw_data, offset, data);
}

RawFile  *rawFileNew(const uint8_t *file_name, const int fd, const int flags, const uint32_t file_size, const word_t cdfs_md_id)
{
    RawFile *raw_file;
    //MEM_CHECK(file_name);
    raw_file = (RawFile *)SAFE_MALLOC(sizeof(RawFile), LOC_RAW_0004);
    if(NULL == raw_file)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT,"error:rawFileNew: new raw file failed\n");
        return NULL;
    }

    if(RAW_FILE_FAIL == rawFileInit(raw_file, file_name, fd, flags,  file_size, cdfs_md_id))
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileNew: init raw file failed\n");
        SAFE_FREE(raw_file, LOC_RAW_0005);
        return NULL;
    }
    return (raw_file);
}

uint8_t   rawFileInit(RawFile *raw_file, const uint8_t *file_name, const int fd, const int flags, const uint32_t file_size, const word_t cdfs_md_id)
{
    RawData *raw_data;
    MEM_CHECK(raw_file);
    raw_data = rawDataNew(file_size, RAW_FILE_HEAD_SIZE);
    if(NULL == raw_data)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT,"error:rawFileInit: new raw data failed\n");
        return RAW_FILE_FAIL;
    }
    raw_file->fd = fd;
    raw_file->open_flags = flags;
    raw_file->cdfs_md_id = cdfs_md_id;

    if(NULL != file_name)
    {
        raw_file->file_name = __dupFileName(file_name);
    }
    else
    {
        raw_file->file_name = NULL;
    }
    raw_file->raw_data  = raw_data;

    return RAW_FILE_SUCC;
}

uint8_t   rawFileReset(RawFile *raw_file)
{
    MEM_CHECK(raw_file);
    return rawDataReset(raw_file->raw_data);
}

uint8_t   rawFileClean(RawFile *raw_file)
{
    if(NULL == raw_file)
    {
        return RAW_FILE_SUCC;
    }

    if(-1 != raw_file->fd)
    {
        /*note: when based on HSDFS mode, prog will never reach here*/
        dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawFileClean: close file %s (fd %d)\n", raw_file->file_name, raw_file->fd);
        ASSERT(0 == close(raw_file->fd));
        raw_file->fd = -1;
    }

    if(NULL != raw_file->raw_data)
    {
        rawDataFree(raw_file->raw_data);
        raw_file->raw_data = NULL;
    }

    if(NULL != raw_file->file_name)
    {
        SAFE_FREE(raw_file->file_name, LOC_RAW_0006);
        raw_file->file_name = NULL;
    }

    return RAW_FILE_SUCC;
}

uint8_t   rawFileFree(RawFile *raw_file)
{
    if(NULL != raw_file)
    {
        rawFileClean(raw_file);
        SAFE_FREE(raw_file, LOC_RAW_0007);
    }
    return RAW_FILE_SUCC;
}

uint8_t   rawFileUnMake(RawFile *raw_file)
{
    if(NULL == raw_file && NULL != raw_file->raw_data)
    {
        rawDataUnMake(raw_file->raw_data);
    }

    return RAW_FILE_SUCC;
}

size_t    rawFileRead(RawFile *raw_file, const offset_t offset, void *des, size_t size, size_t nmemb, const word_t location)
{
    size_t count;
    count = rawDataRead(raw_file->raw_data, offset, des, size, nmemb);
    dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawFileRead: raw_file %lx: read %d bytes at offset %d, %s:%ld\n",
                        raw_file, count * size, offset, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return count;
}

size_t    rawFileWrite(RawFile *raw_file, const offset_t offset, const void *src, size_t size, size_t nmemb, const word_t location)
{
    size_t count;
    count = rawDataWrite(raw_file->raw_data, offset, src, size, nmemb);
    if(0 == count)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileWrite: write %d bytes at offset %d to %s failed\n",
                            count * size, offset, raw_file->file_name);
    }
    return count;
}

size_t    rawFilePuts(RawFile *raw_file, const offset_t offset, const char *src)
{
    size_t len;
    len = rawDataPuts(raw_file->raw_data, offset, src);
    dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawFilePuts: raw_file %lx: put %d bytes at offset %d\n", raw_file, len, offset);
    return len;
}

uint8_t   rawFileSeek(RawFile *raw_file, long offset, int whence)
{
    return rawDataSeek(raw_file->raw_data, offset, whence);
}

RawData  *rawDataNew(const uint32_t max_size, const uint32_t head_size)
{
    RawData *raw_data;
    raw_data = (RawData *)SAFE_MALLOC(sizeof(RawData) + max_size, LOC_RAW_0008);
    if(NULL == raw_data)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT,"error:rawDataNew: new raw file failed\n");
        return NULL;
    }
    rawDataInit(raw_data, max_size, head_size);
    return (raw_data);
}

uint8_t   rawDataInit(RawData *raw_data, const uint32_t max_size, const uint32_t head_size)
{
    raw_data->max_size  = max_size;
    raw_data->head_size = head_size;
    raw_data->cur_size  = head_size;
    RAWDATA_CLEAR_DIRTY(raw_data);
    return RAW_FILE_SUCC;
}

uint8_t   rawDataReset(RawData *raw_data)
{
    raw_data->cur_size  = raw_data->head_size;
    return RAW_FILE_SUCC;
}

uint8_t   rawDataClean(RawData *raw_data)
{
    RAWDATA_CLEAR_DIRTY(raw_data);
    return RAW_FILE_SUCC;
}

uint8_t   rawDataFree(RawData *raw_data)
{
    if(NULL != raw_data)
    {
        rawDataClean(raw_data);
        SAFE_FREE(raw_data, LOC_RAW_0009);
    }
    return RAW_FILE_SUCC;
}

uint8_t   rawDataUnMake(RawData *raw_data)
{
    RAWDATA_CLEAR_DIRTY(raw_data);
    return RAW_FILE_SUCC;
}

/*des_len is IO parameter*/
uint8_t   rawDataCompress(const RawData *raw_data, uint8_t *des, word_t *des_len)
{
    /*ZEXTERN int ZEXPORT compress OF((Bytef *dest,   uLongf *destLen, const Bytef *source, uLong sourceLen));*/
    if(Z_OK != compress(des, des_len, raw_data->buffer, raw_data->cur_size))
    {
        return RAW_FILE_FAIL;
    }
    return RAW_FILE_SUCC;
}

uint8_t   rawDataUnCompress(RawData *raw_data, const uint8_t *src, const word_t src_len)
{
    word_t des_len;

    des_len = raw_data->max_size;

    /*ZEXTERN int ZEXPORT uncompress OF((Bytef *dest,   uLongf *destLen, const Bytef *source, uLong sourceLen));*/
    if(Z_OK != uncompress(raw_data->buffer, &des_len, src, src_len))
    {
        return RAW_FILE_FAIL;
    }

    raw_data->cur_size = des_len;
    return (RAW_FILE_SUCC);
}

#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t   rawDataLoad(RawData *raw_data, const RawFile *raw_file)
{
    uint32_t flen;
    uint8_t *buff;
    int fd;

    fd = raw_file->fd;

    /*fetch length*/
    flen = lseek(fd, 0, SEEK_END);
    if(0 == flen)
    {
        return RAW_FILE_SUCC;
    }

    buff = (uint8_t *)SAFE_MALLOC(flen, LOC_RAW_0010);
    if(NULL == buff)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: alloc %d bytes failed\n", flen);
        return RAW_FILE_FAIL;
    }

    lseek(fd, 0, SEEK_SET);
    read(fd, buff, flen);

    if(RAW_FILE_SUCC != rawDataUnCompress(raw_data, buff, flen))
    {
        SAFE_FREE(buff, LOC_RAW_0011);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: uncompress %ld bytes failed\n", flen);
        return RAW_FILE_FAIL;
    }

    SAFE_FREE(buff, LOC_RAW_0012);

    dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataLoad: uncompress %d bytes => %d bytes, rate = %.2f\n",
                       flen, raw_data->cur_size, (flen + 0.0)/(raw_data->cur_size + 0.0));
    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t   rawDataLoad0(RawData *raw_data, const RawFile *raw_file)
{
    word_t   flen;
    uint8_t *buff;
    uint32_t counter;

    CSTRING *fname_cstr;
    CBYTES  *cbytes;

    fname_cstr = cstring_new(raw_file->file_name, LOC_RAW_0013);
    if(NULL_PTR == fname_cstr)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: new fname string failed\n");
        return RAW_FILE_FAIL;
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        cstring_free(fname_cstr);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: new cbytes failed\n");
        return RAW_FILE_FAIL;
    }

    if(EC_FALSE == cdfs_read(raw_file->cdfs_md_id, fname_cstr, cbytes))
    {
        cstring_free(fname_cstr);
        cbytes_free(cbytes);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawFileOpen: read file %s failed\n", (char *)raw_file->file_name);
        return RAW_FILE_FAIL;
    }

    buff = cbytes_buf(cbytes);
    counter = 0;
    flen = gdbGetWord(buff, &counter);/*get compressed data len from the first word*/

    if(RAW_FILE_SUCC != rawDataUnCompress(raw_data, buff + counter, flen))
    {
        cstring_free(fname_cstr);
        cbytes_free(cbytes);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: uncompress %ld bytes failed\n", flen);
        return RAW_FILE_FAIL;
    }

    cstring_free(fname_cstr);
    cbytes_free(cbytes);

    dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataLoad: uncompress %d bytes => %d bytes, rate = %.2f\n",
                       flen, raw_data->cur_size, (flen + 0.0)/(raw_data->cur_size + 0.0));
    return RAW_FILE_SUCC;
}

uint8_t   rawDataLoad(RawData *raw_data, const RawFile *raw_file)
{
    word_t   flen;
    uint8_t *buff;

    CSTRING *fname_cstr;
    CBYTES  *cbytes;

    fname_cstr = cstring_new(raw_file->file_name, LOC_RAW_0014);
    if(NULL_PTR == fname_cstr)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: new fname string failed\n");
        return RAW_FILE_FAIL;
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        cstring_free(fname_cstr);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: new cbytes failed\n");
        return RAW_FILE_FAIL;
    }

    if(EC_FALSE == cdfs_read(raw_file->cdfs_md_id, fname_cstr, cbytes))
    {
        cstring_free(fname_cstr);
        cbytes_free(cbytes);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: read file %s failed\n", (char *)raw_file->file_name);
        return RAW_FILE_FAIL;
    }

    buff = cbytes_buf(cbytes);
    flen = cbytes_len(cbytes);

    if(RAW_FILE_SUCC != rawDataUnCompress(raw_data, buff, flen))
    {
        cstring_free(fname_cstr);
        cbytes_free(cbytes);
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataLoad: uncompress %ld bytes failed\n", flen);
        return RAW_FILE_FAIL;
    }

    cstring_free(fname_cstr);
    cbytes_free(cbytes);

    dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataLoad: uncompress %d bytes => %d bytes, rate = %.2f\n",
                       flen, raw_data->cur_size, (flen + 0.0)/(raw_data->cur_size + 0.0));
    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/


#if (SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t   rawDataFlush(RawData *raw_data, const RawFile *raw_file)
{
    if(RAWDATA_IS_DIRTY(raw_data))
    {
        uint8_t *des_buff;
        word_t   des_len;
        ssize_t  wrote_len;
        int      fd;

        fd = raw_file->fd;

        des_buff = (uint8_t *)SAFE_MALLOC(raw_data->cur_size, LOC_RAW_0015);
        if(NULL == des_buff)
        {
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: alloc %d bytes failed\n", raw_data->cur_size);
            return RAW_FILE_FAIL;
        }
        des_len = raw_data->cur_size;

        if(RAW_FILE_SUCC != rawDataCompress(raw_data, des_buff, &des_len))
        {
            SAFE_FREE(des_buff, LOC_RAW_0016);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: compress %d bytes failed\n", raw_data->cur_size);
            return RAW_FILE_FAIL;
        }

        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataFlush: compress %d bytes => %d bytes, rate = %.2f\n",
                           raw_data->cur_size, des_len, (des_len + 0.0)/(raw_data->cur_size + 0.0));

        /*flush compressed data*/
        lseek(fd, 0, SEEK_SET);
        wrote_len = write(fd, des_buff, des_len);
        if(0 > wrote_len || (uint32_t)wrote_len != des_len)
        {
            SAFE_FREE(des_buff, LOC_RAW_0017);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: expect to write %d bytes but accept %ld bytes only, errno = %d, errstr = %s\n",
                                des_len, wrote_len, errno, strerror(errno));
            return RAW_FILE_FAIL;
        }
        SAFE_FREE(des_buff, LOC_RAW_0018);

        RAWDATA_CLEAR_DIRTY(raw_data);

        dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawDataFlush: raw data is dirty, flush %d bytes into fd %d where max_size %d\n",
                            des_len, fd, raw_data->max_size);
    }
    else
    {
        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataFlush: raw data is NOT dirty, NOT flush it\n");
    }

    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_OFF == CBGT_BASED_ON_HSDFS_SWITCH)*/

#if (SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)
uint8_t   rawDataFlush0(RawData *raw_data, const RawFile *raw_file)
{
    if(RAWDATA_IS_DIRTY(raw_data))
    {
        uint8_t  *des_buff;
        word_t    des_len;
        word_t    des_offset;
        uint32_t  counter;
        CSTRING  *fname_cstr;
        CBYTES    cbytes;

        fname_cstr = cstring_new(raw_file->file_name, LOC_RAW_0019);
        if(NULL_PTR == fname_cstr)
        {
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: new file name string failed\n");
            return RAW_FILE_FAIL;
        }

        des_offset = sizeof(word_t);

        des_buff = (uint8_t *)SAFE_MALLOC(raw_data->cur_size + des_offset, LOC_RAW_0020);
        if(NULL == des_buff)
        {
            cstring_free(fname_cstr);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: alloc %d bytes failed\n", raw_data->cur_size + des_offset);
            return RAW_FILE_FAIL;
        }
        des_len = raw_data->cur_size;

        if(RAW_FILE_SUCC != rawDataCompress(raw_data, des_buff + des_offset, &des_len))
        {
            cstring_free(fname_cstr);
            SAFE_FREE(des_buff, LOC_RAW_0021);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: compress %d bytes failed\n", raw_data->cur_size);
            return RAW_FILE_FAIL;
        }

        counter = 0;
        gdbPutWord(des_buff, &counter, des_len);/*save length at the first word*/

        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataFlush: compress %d bytes => %d bytes, rate = %.2f\n",
                           raw_data->cur_size, des_len, (des_len + 0.0)/(raw_data->cur_size + 0.0));

        /*flush first word + compressed data*/
        cbytes_init(&cbytes);
        cbytes_mount(&cbytes, des_len + des_offset, des_buff); /*total length = first word len + compressed data len*/
        if(EC_FALSE == cdfs_update(raw_file->cdfs_md_id, fname_cstr, &cbytes))
        {
            cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
            cstring_free(fname_cstr);
            SAFE_FREE(des_buff, LOC_RAW_0022);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: update %s with %ld bytes failed\n",
                                (char *)raw_file->file_name, des_len);
            return RAW_FILE_FAIL;
        }

        cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
        cstring_free(fname_cstr);
        SAFE_FREE(des_buff, LOC_RAW_0023);

        RAWDATA_CLEAR_DIRTY(raw_data);

        dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawDataFlush: raw data is dirty, flush %d bytes into file %s where max_size %d\n",
                            des_len, (char *)raw_file->file_name, raw_data->max_size);
    }
    else
    {
        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataFlush: raw data is NOT dirty, NOT flush it\n");
    }

    return RAW_FILE_SUCC;
}

uint8_t   rawDataFlush(RawData *raw_data, const RawFile *raw_file)
{
    if(RAWDATA_IS_DIRTY(raw_data))
    {
        uint8_t  *des_buff;
        word_t    des_len;
        CSTRING  *fname_cstr;
        CBYTES    cbytes;

        fname_cstr = cstring_new(raw_file->file_name, LOC_RAW_0024);
        if(NULL_PTR == fname_cstr)
        {
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: new file name string failed\n");
            return RAW_FILE_FAIL;
        }

        des_buff = (uint8_t *)SAFE_MALLOC(raw_data->cur_size, LOC_RAW_0025);
        if(NULL == des_buff)
        {
            cstring_free(fname_cstr);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: alloc %d bytes failed\n", raw_data->cur_size);
            return RAW_FILE_FAIL;
        }
        des_len = raw_data->cur_size;

        if(RAW_FILE_SUCC != rawDataCompress(raw_data, des_buff, &des_len))
        {
            cstring_free(fname_cstr);
            SAFE_FREE(des_buff, LOC_RAW_0026);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: compress %d bytes failed\n", raw_data->cur_size);
            return RAW_FILE_FAIL;
        }

        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataFlush: compress %d bytes => %d bytes, rate = %.2f\n",
                           raw_data->cur_size, des_len, (des_len + 0.0)/(raw_data->cur_size + 0.0));

        /*flush first word + compressed data*/
        cbytes_init(&cbytes);
        cbytes_mount(&cbytes, des_len, des_buff);
        if(EC_FALSE == cdfs_update(raw_file->cdfs_md_id, fname_cstr, &cbytes))
        {
            cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
            cstring_free(fname_cstr);
            SAFE_FREE(des_buff, LOC_RAW_0027);
            dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataFlush: update %s with %ld bytes failed\n",
                                (char *)raw_file->file_name, des_len);
            return RAW_FILE_FAIL;
        }

        cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
        cstring_free(fname_cstr);
        SAFE_FREE(des_buff, LOC_RAW_0028);

        RAWDATA_CLEAR_DIRTY(raw_data);

        dbg_log(SEC_0132_RAW, 9)(LOGSTDNULL, "[DEBUG] rawDataFlush: raw data is dirty, flush %d bytes into file %s where max_size %d\n",
                            des_len, (char *)raw_file->file_name, raw_data->max_size);
    }
    else
    {
        dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT, "[DEBUG] rawDataFlush: raw data is NOT dirty, NOT flush it\n");
    }

    return RAW_FILE_SUCC;
}
#endif/*(SWITCH_ON == CBGT_BASED_ON_HSDFS_SWITCH)*/

uint32_t  rawDataMaxSize(const RawData *raw_data)
{
    return (raw_data->max_size);
}

uint32_t  rawDataCurSize(const RawData *raw_data)
{
    return (raw_data->cur_size);
}

uint32_t  rawDataRoomSize(const RawData *raw_data)
{
    return (raw_data->max_size - raw_data->cur_size);
}
uint8_t   rawDataIsFull(const RawData *raw_data, const uint32_t min_size)
{
    if(min_size > rawDataRoomSize(raw_data))
    {
        return 1;/*true*/
    }
    return 0;/*false*/
}

uint8_t   rawDataPut8(RawData *raw_data, const offset_t offset, const uint8_t data)
{
    if(offset + 1 <= raw_data->max_size)
    {
        raw_data->buffer[offset] = data;
        raw_data->cur_size = DMAX(raw_data->cur_size, offset + 1);
        RAWDATA_SET_DIRTY(raw_data);
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}

uint8_t   rawDataPut16(RawData *raw_data, const offset_t offset, const uint16_t data)
{
    if(offset + sizeof(uint16_t) <= raw_data->max_size)
    {
        uint16_t num;
        num = gdb_hton_uint16(data);

        memcpy(raw_data->buffer + offset, &num, sizeof(uint16_t));
        raw_data->cur_size = DMAX(raw_data->cur_size, offset + sizeof(uint16_t));
        RAWDATA_SET_DIRTY(raw_data);
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}

uint8_t   rawDataPut32(RawData *raw_data, const offset_t offset, const uint32_t data)
{
    if(offset + sizeof(uint32_t) <= raw_data->max_size)
    {
        uint32_t num;
        num = gdb_hton_uint32(data);

        memcpy(raw_data->buffer + offset, &num, sizeof(uint32_t));
        raw_data->cur_size = DMAX(raw_data->cur_size, offset + sizeof(uint32_t));

        RAWDATA_SET_DIRTY(raw_data);
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}

/*put uint8_t array without storing its length*/
uint8_t   rawDataPut8s(RawData *raw_data, const offset_t offset, const uint8_t *data, const uint32_t len)
{
    if(offset + len <= raw_data->max_size)
    {
        memcpy(raw_data->buffer + offset, data, len);
        raw_data->cur_size = DMAX(raw_data->cur_size, offset + len);

        RAWDATA_SET_DIRTY(raw_data);
        return RAW_FILE_SUCC;
    }
    dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataPut8s: offset %d + len %d > max_size %d\n",
                        offset, len, raw_data->max_size);
    return RAW_FILE_FAIL;
}


/*put uint8_t array and its length*/
uint8_t   rawDataPut8slen(RawData *raw_data, const offset_t offset, const uint8_t *data, const uint32_t len)
{
    if(offset + sizeof(uint32_t) + len <= raw_data->max_size)
    {
        rawDataPut32(raw_data, offset, len);

        memcpy(raw_data->buffer + offset + sizeof(uint32_t), data, len);
        raw_data->cur_size = DMAX(raw_data->cur_size, offset + sizeof(uint32_t) + len);

        RAWDATA_SET_DIRTY(raw_data);

        return RAW_FILE_SUCC;
    }

    dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataPut8slen: cur_size %d + %d + len %d > max_size %d\n",
                        raw_data->cur_size, sizeof(uint32_t), len, raw_data->max_size);
    return RAW_FILE_FAIL;
}

uint8_t   rawDataUpdate8s(RawData *raw_data, const uint32_t offset, const uint8_t *data, const uint32_t len)
{
    if(offset + len > raw_data->cur_size)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataUpdate8s: offset %d + len %d > cur_size %d\n",
                            offset, len, raw_data->cur_size);
        return RAW_FILE_FAIL;
    }
    memcpy(raw_data->buffer + offset, data, len);
    RAWDATA_SET_DIRTY(raw_data);
    return RAW_FILE_SUCC;
}

uint8_t   rawDataUpdate8slen(RawData *raw_data, const uint32_t offset, const uint8_t *data, const uint32_t len)
{
    uint32_t num;
    uint8_t *buffer;

    if(offset + sizeof(uint32_t) + len > raw_data->cur_size)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataUpdate8slen: offset %d + %d + len %d > cur_size %d\n",
                            offset, sizeof(uint32_t), len, raw_data->cur_size);
        return RAW_FILE_FAIL;
    }

    num = gdb_hton_uint32(len);

    buffer = raw_data->buffer + offset;
    memcpy(buffer, &num, sizeof(uint32_t));

    buffer += sizeof(uint32_t);
    memcpy(buffer, data, len);

    RAWDATA_SET_DIRTY(raw_data);
    return RAW_FILE_SUCC;
}

uint8_t   rawDataGet8(const RawData *raw_data, const uint32_t offset, uint8_t *data)
{
    if(offset + 1 <= raw_data->cur_size)
    {
        (*data) = raw_data->buffer[offset];
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}

uint8_t   rawDataGet16(const RawData *raw_data, const uint32_t offset, uint16_t *data)
{
    if(offset + sizeof(uint16_t) <= raw_data->cur_size)
    {
        uint16_t num;

        memcpy(&num, raw_data->buffer + offset, sizeof(uint16_t));
        (*data) = gdb_ntoh_uint16(num);
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}

uint8_t   rawDataGet32(const RawData *raw_data, const uint32_t offset, uint32_t *data)
{
    if(offset + sizeof(uint32_t) <= raw_data->cur_size)
    {
        uint32_t num;

        memcpy(&num, raw_data->buffer + offset, sizeof(uint32_t));
        (*data) = gdb_ntoh_uint32(num);
        return RAW_FILE_SUCC;
    }
    return RAW_FILE_FAIL;
}

/*put uint8_t array which is not stored with length*/
uint8_t   rawDataGet8s(const RawData *raw_data, const uint32_t offset, uint8_t *data, const uint32_t max_len, uint32_t *len)
{
    uint32_t data_len;

    if(offset >= raw_data->cur_size)
    {
        return RAW_FILE_FAIL;
    }

    data_len = ((max_len < raw_data->cur_size - offset)? max_len : raw_data->cur_size - offset);
    memcpy(data, raw_data->buffer + offset, data_len);
    (*len) = data_len;
    return RAW_FILE_SUCC;
}


/*put uint8_t array which is stored with length*/
uint8_t   rawDataGet8slen(const RawData *raw_data, const uint32_t offset, uint8_t *data, const uint32_t max_len, uint32_t *len)
{
    uint32_t data_len;

    //dbg_log(SEC_0132_RAW, 9)(LOGSTDOUT,"[DEBUG] rawDataGet8slen: cur_size = %ld, offset = %ld\n", raw_data->cur_size, offset);

    if(RAW_FILE_FAIL == rawDataGet32(raw_data, offset, &data_len))
    {
        return RAW_FILE_FAIL;
    }
    data_len = ((data_len > max_len) ? max_len:data_len);

    if(offset + sizeof(uint32_t) + data_len <= raw_data->cur_size)
    {
        memcpy(data, raw_data->buffer + offset + sizeof(uint32_t), data_len);
        (*len) = data_len;
        return RAW_FILE_SUCC;
    }

    return RAW_FILE_FAIL;
}

size_t    rawDataRead(RawData *raw_data, const offset_t offset, void *des, size_t size, size_t nmemb)
{
    size_t count;
    size_t len;

    if(raw_data->cur_size <= offset)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataRead: cur_size %d, but access offset %d overflow\n", raw_data->cur_size, offset);
        return 0;
    }

    if(raw_data->cur_size < offset + size * nmemb)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataRead: cur_size %d, but access offset(%d) + size(%d) * nmemb(%d) = %d  overflow\n",
                            raw_data->cur_size, offset, size, nmemb, offset + size * nmemb);
    }

    count = DMIN(nmemb, (raw_data->cur_size - offset)/size);
    len = size * count;
    BCOPY(raw_data->buffer + offset, des, len);

    return count;
}

size_t    rawDataWrite(RawData *raw_data, const offset_t offset, const void *src, size_t size, size_t nmemb)
{
    size_t count;
    size_t len;

    if(raw_data->max_size <= offset)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataWrite: max_size %d, but access offset %d overflow\n", raw_data->max_size, offset);
        return 0;
    }

    if(0 == size || 0 == nmemb)
    {
        return 0;
    }

    if(raw_data->max_size <= offset + size * nmemb)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataWrite: max_size %d, but access offset(%d) + size(%d) * nmemb(%d) = %d  overflow\n",
                            raw_data->max_size, offset, size, nmemb, offset + size * nmemb);
    }

    count = DMIN(nmemb, (raw_data->max_size - offset)/size);
    len = size * count;
    BCOPY(src, raw_data->buffer + offset, len);
    if(offset + len > raw_data->cur_size)
    {
        raw_data->cur_size = offset + len;
    }
    RAWDATA_SET_DIRTY(raw_data);

    return count;
}

size_t    rawDataPuts(RawData *raw_data, const offset_t offset, const char *src)
{
    size_t len;

    if(raw_data->max_size <= offset)
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataPuts: max_size %d, but access offset %d overflow\n", raw_data->max_size, offset);
        return 0;
    }

    if(raw_data->max_size <= offset + strlen(src))
    {
        dbg_log(SEC_0132_RAW, 0)(LOGSTDOUT, "error:rawDataPuts: max_size %d, but access offset(%d) + strlen(%d) = %d  overflow\n",
                            raw_data->max_size, offset, strlen(src), offset + strlen(src));
    }

    len = DMIN(strlen(src), raw_data->max_size - offset);
    BCOPY(src, raw_data->buffer + offset, len);
    if(offset + len > raw_data->cur_size)
    {
        raw_data->cur_size = offset + len;
    }
    RAWDATA_SET_DIRTY(raw_data);

    return len;
}

uint8_t   rawDataSeek(RawData *raw_data, long offset, int whence)
{
    return RAW_FILE_SUCC;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

