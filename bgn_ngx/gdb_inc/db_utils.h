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


#ifndef _GNUPDATEDB_UTILS_H_
#define _GNUPDATEDB_UTILS_H_

#include <stdio.h>

/**
 * Returns 1 byte (8 bits) from a buffer.
 *
 * @param buffer  The buffer.
 * @param counter A pointer to the current offset.
 *
 * @return The byte.
 */
uint8_t gdbGet8(const uint8_t *buffer, uint32_t *counter);

/**
 * Returns 2 bytes (16 bits) from a buffer.
 *
 * @param buffer  The buffer.
 * @param counter A pointer to the current offset.
 *
 * @return A short value (2 bytes).
 */
uint16_t gdbGet16(const uint8_t *buffer, uint32_t *counter);

/**
 * Returns 4 bytes (32 bits) from a buffer.
 *
 * @param buffer  The buffer.
 * @param counter A pointer to the current offset.
 *
 * @return A long value (4 bytes).
 */
uint32_t gdbGet32(const uint8_t *buffer, uint32_t *counter);

offset_t gdbGetOffset(const uint8_t *buffer, uint32_t *counter);

word_t   gdbGetWord(const uint8_t *buffer, uint32_t *counter);

ctime_t  gdbGetTs(const uint8_t *buffer, uint32_t *counter);

void     gdbGet8s(uint8_t *buffer, uint32_t *counter, uint8_t *data, const uint32_t len);

void     gdbGetPad(uint8_t *buffer, uint32_t *counter, uint8_t *data, const uint32_t len);

/**
 * Writes 1 byte (8 bits) to a buffer.
 *
 * @param buffer  The buffer.
 * @param counter A pointer to the current offset.
 * @param c       The character to write.
 */
void gdbPut8(uint8_t *buffer, uint32_t *counter, uint8_t c);

/**
 * Writes 2 bytes (16 bits) to a buffer.
 *
 * @param buffer  The buffer.
 * @param counter A pointer to the current offset.
 * @param s       The short to write.
 */
void gdbPut16(uint8_t *buffer, uint32_t *counter, uint16_t s);

/**
 * Writes 4 bytes (32 bits) to a buffer.
 *
 * @param buffer  The buffer.
 * @param counter A pointer to the current offset.
 * @param l       The long to write.
 */
void gdbPut32(uint8_t *buffer, uint32_t *counter, uint32_t l);

void gdbPutOffset(uint8_t *buffer, uint32_t *counter, offset_t l);
void gdbPutWord(uint8_t *buffer, uint32_t *counter, word_t l);

void gdbPutTs(uint8_t *buffer, uint32_t *counter, ctime_t ts);

void gdbPut8s(uint8_t *buffer, uint32_t *counter, const uint8_t *data, const uint32_t len);

void gdbPutPad(uint8_t *buffer, uint32_t *counter, const uint8_t ch, const uint32_t len);

/**
 * Pads data in a file.
 *
 * @param fp    The file pointer.
 * @param count The number of bytes to pad.
 */
void gdbPad(RawFile *fp, const offset_t offset, uint32_t count);

/**
 * Compresses a string using prefix and suffix compression.
 *
 * @param base    The base string.
 * @param baseLen The base length.
 * @param key     The key to compress.
 * @param keyLen  The key length.
 * @param outKey  The destination key.
 * @param outLen  The destination key length.
 */
void gdbCompressString(const uint8_t *base, uint16_t baseLen,
                       const uint8_t *key, uint16_t keyLen,
                       uint8_t **outKey, uint16_t *outLen);

/**
 * Uncompresses a string.
 *
 * @param base    The base string.
 * @param baseLen The base length.
 * @param key     The key.
 * @param keyLen  The key length.
 * @param outKey  The destination key.
 * @param outLen  The destination key length.
 */
void gdbUncompressString(const uint8_t *base, uint16_t baseLen,
                         const uint8_t *key, uint16_t keyLen,
                         uint8_t **outKey, uint16_t *outLen);

#endif /* _GNUPDATEDB_UTILS_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
