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

STATIC_CAST static void __safe_strncpy(uint8_t *des, const uint8_t *src, size_t n, const word_t location)
{
    memcpy(des, src, n);
    return;
}

uint8_t
gdbGet8(const uint8_t *buffer, uint32_t *counter)
{
    uint8_t i = buffer[*counter];

    (*counter)++;

    return i;
}

uint16_t
gdbGet16(const uint8_t *buffer, uint32_t *counter)
{
    uint16_t s;

    memcpy(&s, buffer + *counter, sizeof(uint16_t));
    s = gdb_ntoh_uint16(s);

    *counter += sizeof(uint16_t);

    return s;

#if 0
    return ntohs(((unsigned short)gdbGet8(buffer, counter) |
                  ((unsigned short)gdbGet8(buffer, counter) << 8)));
#endif
}

uint32_t
gdbGet32(const uint8_t *buffer, uint32_t *counter)
{
    uint32_t l;

    memcpy(&l, buffer + *counter, sizeof(uint32_t));
    l = gdb_ntoh_uint32(l);

    *counter += sizeof(uint32_t);

    return l;

#if 0
    return (((unsigned long)gdbGet16(buffer, counter) |
             ((unsigned long)gdbGet16(buffer, counter) << 16)));
#endif
}

offset_t gdbGetOffset(const uint8_t *buffer, uint32_t *counter)
{
#if (32 != OFFSETSIZE)
#error "error:gdbGetOffset: OFFSETSIZE is not 32, you should implement gdbGetOffset again"
#endif/*(32 != OFFSETSIZE)*/
    return gdbGet32(buffer, counter);
}


word_t
gdbGetWord(const uint8_t *buffer, uint32_t *counter)
{
    word_t l;

    memcpy(&l, buffer + *counter, sizeof(word_t));
    l = gdb_ntoh_word(l);

    *counter += sizeof(word_t);

    return l;

#if 0
    return (((unsigned long)gdbGet16(buffer, counter) |
             ((unsigned long)gdbGet16(buffer, counter) << 16)));
#endif
}

ctime_t
gdbGetTs(const uint8_t *buffer, uint32_t *counter)
{
    ctime_t ts;

    memcpy(&ts, buffer + *counter, sizeof(ctime_t));
    ts = gdb_ntoh_time(ts);

    *counter += sizeof(ctime_t);

    return ts;

#if 0
    return (((unsigned long)gdbGet16(buffer, counter) |
             ((unsigned long)gdbGet16(buffer, counter) << 16)));
#endif
}

void
gdbGet8s(uint8_t *buffer, uint32_t *counter, uint8_t *data, const uint32_t len)
{
    memcpy(data, buffer + *counter, len);
    *counter += len;
    return;
}

void
gdbGetPad(uint8_t *buffer, uint32_t *counter, uint8_t *data, const uint32_t len)
{
    if(NULL_PTR != data)
    {
        memcpy(data, buffer + *counter, len);
    }
    *counter += len;
    return;
}

void
gdbPut8(uint8_t *buffer, uint32_t *counter, uint8_t c)
{
    buffer[*counter] = c;

    (*counter)++;
    return;
}

void
gdbPut16(uint8_t *buffer, uint32_t *counter, uint16_t s)
{
    s = gdb_hton_uint16(s);

    memcpy(buffer + *counter, &s, sizeof(uint16_t));
    *counter += sizeof(uint16_t);

#if 0
    gdbPut8(buffer, counter, (unsigned char)s);
    gdbPut8(buffer, counter, (unsigned char)(s >> 8));
#endif
    return;
}

void
gdbPut32(uint8_t *buffer, uint32_t *counter, uint32_t l)
{
    l = gdb_hton_uint32(l);

    memcpy(buffer + *counter, &l, sizeof(uint32_t));
    *counter += sizeof(uint32_t);

#if 0
    gdbPut16(buffer, counter, (unsigned short)l);
    gdbPut16(buffer, counter, (unsigned short)(l >> 16));
#endif
    return;
}

void
gdbPutOffset(uint8_t *buffer, uint32_t *counter, offset_t l)
{
#if (32 != OFFSETSIZE)
#error "error:gdbPutOffset: OFFSETSIZE is not 32, you should implement gdbGetOffset again"
#endif/*(32 != OFFSETSIZE)*/
    return gdbPut32(buffer, counter, l);
}

void
gdbPutWord(uint8_t *buffer, uint32_t *counter, word_t l)
{
    l = gdb_hton_word(l);

    memcpy(buffer + *counter, &l, sizeof(word_t));
    *counter += sizeof(word_t);
    return;
}

void
gdbPutTs(uint8_t *buffer, uint32_t *counter, ctime_t ts)
{
    ts = gdb_hton_time(ts);

    memcpy(buffer + *counter, &ts, sizeof(ctime_t));
    *counter += sizeof(ctime_t);
    return;
}

void
gdbPut8s(uint8_t *buffer, uint32_t *counter, const uint8_t *data, const uint32_t len)
{
    memcpy(buffer + *counter, data, len);
    *counter += len;
    return;
}

void
gdbPutPad(uint8_t *buffer, uint32_t *counter, const uint8_t ch, const uint32_t len)
{
    memset(buffer + (*counter), ch, len);
    *counter += len;
    return;
}

void
gdbPad(RawFile *fp, const offset_t offset, uint32_t count)
{
    uint8_t *buff;

    if (fp == NULL || count == 0)
    {
        return;
    }
    MEM_CHECK(buff = (uint8_t *)SAFE_MALLOC(count, LOC_DB_0001));
    memset(buff, 0, count);

    rawFileWrite(fp, offset, buff, 1, count, LOC_DB_0002);

    SAFE_FREE(buff, LOC_DB_0003);
    return;
}

void
gdbCompressString(const uint8_t *base, uint16_t baseLen,
                  const uint8_t *key, uint16_t keyLen,
                  uint8_t **outKey, uint16_t *outLen)
{
    uint16_t preLen, sufLen;
    uint16_t maxLen, minLen;
    uint16_t newLen;
    const uint8_t *c1, *c2;
    uint8_t *newKey;

    if (base == NULL || baseLen == 0 || key == NULL || keyLen == 0 ||
        outKey == NULL || outLen == NULL)
    {
        return;
    }

    sufLen = 0;

    maxLen = (baseLen > keyLen ? baseLen : keyLen);
    minLen = (baseLen < keyLen ? baseLen : keyLen);

    maxLen = (maxLen < 255 ? maxLen : 255);
    minLen = (minLen < 255 ? minLen : 255);

    /*
     * Get the prefix length.
     *
     * Okay, so it's a little hacky :) It should be more efficient though.
     */
    for (c1 = base, c2 = key, preLen = 0;
         (preLen < minLen) && (*c1 == *c2);
         c1++, c2++, preLen++)
        ;

    newLen = keyLen - preLen + 1;

    MEM_CHECK(newKey = (uint8_t *)SAFE_MALLOC(newLen, LOC_DB_0004));

    newKey[0] = preLen;
    __safe_strncpy(newKey + 1, key + preLen, keyLen - preLen, LOC_DB_0005);

    *outKey = newKey;
    *outLen = newLen;

    return;
}

void
gdbUncompressString(const uint8_t *base, uint16_t baseLen,
                    const uint8_t *key, uint16_t keyLen,
                    uint8_t **outKey, uint16_t *outLen)
{
    uint16_t preLen, newLen;
    uint8_t *newKey;

    if (base == NULL || baseLen == 0 || key == NULL || keyLen == 0 ||
        outKey == NULL || outLen == NULL)
    {
        return;
    }

    preLen = key[0];

    newLen = preLen + keyLen - 1;

    MEM_CHECK(newKey = (uint8_t *)SAFE_MALLOC(newLen, LOC_DB_0006));

    __safe_strncpy(newKey, base, preLen, LOC_DB_0007);
    __safe_strncpy(newKey + preLen, key + 1, keyLen - 1, LOC_DB_0008);

    *outKey = newKey;
    *outLen = newLen;

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

