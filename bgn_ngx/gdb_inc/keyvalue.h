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

#ifndef _KEYVALUE_H_
#define _KEYVALUE_H_

#include "db.h"
#include <pcre.h>

#define KEY_TYPE_IS_ERR     ((uint8_t) 0)
#define KEY_TYPE_IS_PUT     ((uint8_t) 1)
#define KEY_TYPE_IS_RMV     ((uint8_t) 2)

/*key of kv format: klen(2B) | vlen(4B) | rlen(2B) | row(rlen) | cflen(1B) | cf(cflen) | cq(cqlen) | ts(4B/8B) | type(1B)*/
#define KV_FORMAT_KLEN      (2) /*2B*/
#define KV_FORMAT_VLEN      (4) /*4B*/
#define KV_FORMAT_RLEN      (2) /*2B*/
#define KV_FORMAT_CFLEN     (1) /*1B*/
#if (32 == WORDSIZE)
#define KV_FORMAT_TSLEN     (4) /*8B*/
#endif/*(32 == WORDSIZE)*/
#if (64 == WORDSIZE)
#define KV_FORMAT_TSLEN     (8) /*8B*/
#endif/*(64 == WORDSIZE)*/
#define KV_FORMAT_TPLEN     (1) /*1B*/

#if (SWITCH_ON == HS_KV_SWITCH)

#define keyDup        kvDupHs
#define keyLen        kvGettLenHs
#define keyNew        kvNewHs2
#define keyFree       kvFreeHs
#define keyCmp        kvCmpKeyHs
#define keyScopeCmp   kvCmpRowkeyScopeHs
#define keyPrint      kvPrintHs
#define keyEncodeSize kvEncodeSize
#define keyEncode     kvEncode
#define keyDecode     kvDecode

#else/*(SWITCH_OFF == HS_KV_SWITCH)*/
#if (SWITCH_ON == HS_KEY_SWITCH)

#define keyDup        keyDupHs
#define keyLen        keyLenHs
#define keyNew        keyNewHs
#define keyFree       keyFreeHs
#define keyCmp        keyCmpHs2
#define keyPrint      keyPrintHs

#endif/*(SWITCH_ON == HS_KEY_SWITCH)*/

#if (SWITCH_OFF == HS_KEY_SWITCH)

#define keyDup        keyDupBase
#define keyLen        keyLenBase
#define keyNew        keyNewBase
#define keyFree       keyFreeBase
#define keyCmp        keyCmpBase
#define keyPrint      keyPrintBase

#endif/*(SWITCH_OFF == HS_KEY_SWITCH)*/
#endif/*(SWITCH_ON == HS_KV_SWITCH)*/

typedef struct
{
    uint16_t klen;
    uint16_t rlen;
    uint32_t vlen;
    uint16_t cqlen;
    uint8_t  cflen;
    uint8_t  type;
    uint32_t rsvd;

    uint8_t *row;
    uint8_t *col_family;
    uint8_t *col_qualifier;
    ctime_t  time_stamp;
    uint8_t *value;
}KeyValue;

uint8_t *keyDupBase(const uint8_t *key, const word_t location);

uint16_t keyLenBase(const uint8_t *key);

uint8_t *keyNewBase(const uint16_t len, const word_t location);

void keyFreeBase(uint8_t *key, const word_t location);

int  keyCmpBase(const uint8_t *key_1st, const uint8_t *key_2nd);

/*key of kv format: klen(2B) | vlen(4B) | rlen(2B) | row(rlen) | cflen(1B) | cf(cflen) | cq(cqlen) | ts(8B) | type(1B)*/

void    keyPutHs(uint8_t *key, const uint32_t vlen,
                      const uint16_t rlen, const uint8_t *row,
                      const uint8_t  cflen, const uint8_t *col_family,
                      const uint16_t cqlen, const uint8_t *col_qualifier,
                      const ctime_t  time_stamp,
                      const uint8_t  type);

uint16_t keyGetkLenHs(const uint8_t *key);

uint32_t keyGetvLenHs(const uint8_t *key);

/*total key length: sizeof(klen); + sizeof(vlen); + klen = 2 + 4 + klen = 6 + klen*/
uint16_t keyGettLenHs(const uint8_t *key);

uint16_t keyGetrLenHs(const uint8_t *key);

uint8_t keyGetcfLenHs(const uint8_t *key);

uint16_t keyGetcqLenHs(const uint8_t *key);

uint8_t keyGettsLenHs(const uint8_t *key);

uint8_t keyGettpLenHs(const uint8_t *key);

const uint8_t *keyGetRowHs(const uint8_t *key);

const uint8_t *keyGetColFamilyHs(const uint8_t *key);

const uint8_t *keyGetColQualifierHs(const uint8_t *key);

ctime_t keyGetTimeStampHs(const uint8_t *key);

uint8_t  keyGetType(const uint8_t *key);

uint8_t *keyDupHs(const uint8_t *key, const word_t location);

/*total length of key*/
uint16_t keyLenHs(const uint8_t *key);

uint8_t *keyNewHs(const uint16_t klen, const word_t location);

void keyFreeHs(uint8_t *key, const word_t location);

int  keyCmpHs(const uint8_t *key_1st, const uint8_t *key_2nd);

int  keyCmpHs2(const uint8_t *key_1st, const uint8_t *key_2nd);

int  keyRegex(const uint8_t *key, pcre *row_re, pcre *colf_re, pcre *colq_re);

void keyPrintHs(LOG *log, const uint8_t *key);

KeyValue *keyValueNewHs(const uint32_t vlen,
                      const uint16_t rlen, const uint8_t *row,
                      const uint8_t  cflen, const uint8_t *col_family,
                      const uint16_t cqlen, const uint8_t *col_qualifier,
                      const ctime_t  time_stamp,
                      const uint8_t  type,
                      const uint8_t *value,
                      const word_t location);

KeyValue *keyValueMakeHs(const uint32_t vlen,
                      const uint16_t rlen, const uint8_t *row,
                      const uint8_t  cflen, const uint8_t *col_family,
                      const uint16_t cqlen, const uint8_t *col_qualifier,
                      const ctime_t  time_stamp,
                      const uint8_t  type,
                      const uint8_t *value,
                      const word_t location);

void keyValueUnMakeHs(KeyValue *keyValue, const word_t location);

void keyValueCleanHs(KeyValue *keyValue, const word_t location);

void keyValueFreeHs(KeyValue *keyValue, const word_t location);

void keyValueInitHs(KeyValue *keyValue, const uint32_t vlen,
                              const uint16_t rlen, const uint8_t *row,
                              const uint8_t  cflen, const uint8_t *col_family,
                              const uint16_t cqlen, const uint8_t *col_qualifier,
                              const ctime_t  time_stamp,
                              const uint8_t  type,
                              const uint8_t *value);

void keyValueSetHs(KeyValue *keyValue, const uint32_t vlen,
                              const uint16_t rlen, const uint8_t *row,
                              const uint8_t  cflen, const uint8_t *col_family,
                              const uint16_t cqlen, const uint8_t *col_qualifier,
                              const ctime_t  time_stamp,
                              const uint8_t  type,
                              const uint8_t *value,
                              const word_t location);

void keyValuePutKeyHs(uint8_t *key, const KeyValue *keyValue);

KeyValue *keyValueGetKeyHs(uint8_t *key, const word_t location);

void keyValueSetValueHs(KeyValue *keyValue, const uint8_t *value);

uint16_t keyValueGetkLenHs(const KeyValue *keyValue);
uint32_t keyValueGetvLenHs(const KeyValue *keyValue);
uint16_t keyValueGettLenHs(const KeyValue *keyValue);
uint16_t keyValueGetrLenHs(const KeyValue *keyValue);
uint8_t  keyValueGetcfLenHs(const KeyValue *keyValue);
uint16_t keyValueGetcqLenHs(const KeyValue *keyValue);
uint8_t  keyValueGettsLenHs(const KeyValue *keyValue);
uint8_t  keyValueGettpLenHs(const KeyValue *keyValue);
void     keyValuePrintHs(LOG *log, const KeyValue *keyValue);

uint8_t *kvNewHs(const KeyValue *keyValue, const word_t location);
uint8_t *kvNewHs2(const uint16_t tlen, const word_t location);

void     kvPutHs(uint8_t *kv, const KeyValue *keyValue);
void     kvFreeHs(uint8_t *kv, const word_t location);
void     kvPrintHs(LOG *log, const uint8_t *kv);

/*if kv_2nd is the start substring kv_1st, then matched and return 0, otherwise return the compare result*/
int      kvMatchHs(const uint8_t *kv_1st, const uint8_t *kv_2nd);

/*if kv_1st >= kv_2nd, return 0, else return 1*/
int      kvGtHs(const uint8_t *kv_1st, const uint8_t *kv_2nd);

uint16_t kvGetkLenHs(const uint8_t *kv);

uint32_t kvGetvLenHs(const uint8_t *kv);

/*total kv length: sizeof(klen); + sizeof(vlen); + klen = 2 + 4 + klen = 6 + klen*/
uint32_t kvGettLenHs(const uint8_t *kv);

uint16_t kvGetrLenHs(const uint8_t *kv);

uint8_t kvGetcfLenHs(const uint8_t *kv);

uint16_t kvGetcqLenHs(const uint8_t *kv);

uint8_t kvGettsLenHs(const uint8_t *kv);

uint8_t kvGettpLenHs(const uint8_t *kv);


const uint8_t *kvGetRowHs(const uint8_t *kv);

const uint8_t *kvGetColFamilyHs(const uint8_t *kv);

const uint8_t *kvGetColQualifierHs(const uint8_t *kv);

ctime_t kvGetTimeStampHs(const uint8_t *kv);

uint8_t kvGetTypeHs(const uint8_t *kv);

const uint8_t *kvGetValueHs(const uint8_t *kv);

uint8_t *kvDupHs(const uint8_t *kv, const word_t location);

int  kvCmpKeyHs(const uint8_t *kv_1st, const uint8_t *kv_2nd);

int  kvCmpRowkeyScopeHs(const uint8_t *kv_1st, const uint8_t *kv_2nd);

EC_BOOL kvEncode(const uint8_t *kv, uint8_t *buff, const uint32_t size, uint32_t *pos);

EC_BOOL kvEncodeSize(const uint8_t *kv, uint32_t *size);

EC_BOOL kvDecode(uint8_t **kv, uint8_t *buff, const uint32_t size, uint32_t *pos);


int  kvRegex(const uint8_t *key, pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re);

#endif /* _KEYVALUE_H_ */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
