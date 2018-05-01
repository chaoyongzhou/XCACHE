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

#include <ctype.h>
#include <pcre.h>

STATIC_CAST static void __print_kv_chars(LOG *log, const uint8_t *buff, const uint32_t len)
{
    uint32_t pos;
    for(pos = 0; pos < len; pos ++)
    {
        uint8_t ch;
        ch = *(buff + pos);
        if(CHAR_IS_VISIBLE(ch))
        {
            sys_print(log,"%c", ch);
        }
        else
        {
            sys_print(log,"&%02x", ch);
        }
    }
}

uint8_t *keyDupBase(const uint8_t *key, const word_t location)
{
    uint8_t *key_t;
    size_t len;

    if(NULL_PTR == key)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyDupBase:key is null at %ld\n", location);
        return NULL_PTR;
    }

    len = strlen((char *)key);

    if(0 == len)
    {
        dbg_log(SEC_0133_KEYVALUE, 1)(LOGSTDOUT,"warn:keyDupBase:key %p len is zero at %ld\n", key, location);
        //return NULL_PTR;
    }

    len ++;

    if(len & (~0xFFFF))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyDupBase:key len %ld overflow at %ld\n", len, location);
        return NULL_PTR;
    }

    key_t = (uint8_t *)SAFE_MALLOC(len, location);
    if(NULL_PTR == key_t)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyDupBase: alloc %ld bytes failed at %ld\n", len, location);
        return (NULL_PTR);
    }

    memcpy(key_t, key, len);
    return (key_t);
}

uint16_t keyLenBase(const uint8_t *key)
{
    size_t len;

    if(NULL_PTR == key)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyLenBase:key is null\n");
        return 0;
    }

    len = strlen((char *)key);

    if(0 == len)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyLenBase:key len is zero\n");
        return 0;
    }

    len ++;

    if(len & (~0xFFFF))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyLenBase:key len %ld overflow\n", len);
        return 0xFFFF;
    }

    return (uint16_t)(len & 0xFFFF);
}

uint8_t *keyNewBase(const uint16_t len, const word_t location)
{
    size_t size;
    uint8_t *key;

    if(0 == len)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyNewBase:len is zero at %ld\n", location);
        return NULL_PTR;
    }

    if(1 == len)
    {
        dbg_log(SEC_0133_KEYVALUE, 1)(LOGSTDOUT,"warn:keyNewBase:len is one at %ld\n", location);
    }

    size = len;

    key = (uint8_t *)SAFE_MALLOC(size, location);
    if(NULL_PTR == key)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyNewBase:malloc %ld bytes failed at %ld\n", size, location);
        return NULL_PTR;
    }

    return (key);
}

void keyFreeBase(uint8_t *key, const word_t location)
{
    size_t len;

    if(NULL_PTR == key)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyFreeBase:key is null at %ld\n", location);
        return;
    }

    len = strlen((char *)key);

    if(0 == len)
    {
        dbg_log(SEC_0133_KEYVALUE, 1)(LOGSTDOUT,"warn:keyFreeBase:key %p len is zero at %ld\n", key, location);
        //return;
    }

    len ++;

    if(len & (~0xFFFF))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyFreeBase:key len %ld overflow at %ld\n", len, location);
        return;
    }

    SAFE_FREE(key, location);

    return ;
}

int keyCmpBase(const uint8_t *key_1st, const uint8_t *key_2nd)
{
    size_t len_1st;
    size_t len_2nd;

    if(NULL_PTR == key_1st)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyCmpBase:key_1st is null\n");
        exit(1);
    }

    if(NULL_PTR == key_2nd)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyCmpBase:key_2nd is null\n");
        exit(2);
    }

    len_1st = strlen((char *)key_1st);
    if(0 == len_1st)
    {
        dbg_log(SEC_0133_KEYVALUE, 1)(LOGSTDOUT,"warn:keyCmpBase:key_1st len is zero\n");
        //exit(1);
    }

    len_1st ++;
    if(len_1st & (~0xFFFF))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyCmpBase:key_1st len %ld overflow\n", len_1st);
        exit(1);
    }

    len_2nd = strlen((char *)key_2nd);
    if(0 == len_2nd)
    {
        dbg_log(SEC_0133_KEYVALUE, 1)(LOGSTDOUT,"warn:keyCmpBase:key_2nd len is zero\n");
        //exit(1);
    }

    len_2nd ++;
    if(len_2nd & (~0xFFFF))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyCmpBase:key_2nd len %ld overflow\n", len_2nd);
        exit(1);
    }

    return strcmp((char *)key_1st, (char *)key_2nd);
}

void keyPrintBase(LOG *log, const uint8_t *key)
{
    sys_log(log, "%s", (char *)key);
}

void    keyPutHs(uint8_t *key, const uint32_t vlen,
                  const uint16_t rlen, const uint8_t *row,
                  const uint8_t  cflen, const uint8_t *col_family,
                  const uint16_t cqlen, const uint8_t *col_qualifier,
                  const ctime_t time_stamp,
                  const uint8_t  type)
{
    uint16_t klen;
    uint32_t counter;

    klen = KV_FORMAT_RLEN + rlen + KV_FORMAT_CFLEN + cflen + cqlen + KV_FORMAT_TSLEN + KV_FORMAT_TPLEN;

    counter = 0;
    gdbPut16(key, &counter, klen);
    gdbPut32(key, &counter, vlen);
    gdbPut16(key, &counter, rlen);
    gdbPut8s(key, &counter, row, rlen);
    gdbPut8 (key, &counter, cflen);
    gdbPut8s(key, &counter, col_family, cflen);
    gdbPut8s(key, &counter, col_qualifier, cqlen);
    gdbPutTs(key, &counter, time_stamp);
    gdbPut8 (key, &counter, type);
    return;
}

uint16_t keyGetkLenHs(const uint8_t *key)
{
    uint32_t counter;

    counter = 0;
    return gdbGet16(key, &counter);
}

uint32_t keyGetvLenHs(const uint8_t *key)
{
    uint32_t counter;

    counter = KV_FORMAT_KLEN;
    return gdbGet32(key, &counter);
}

/*total key length: sizeof(klen) + sizeof(vlen) + klen = 2 + 4 + klen = 6 + klen*/
uint16_t keyGettLenHs(const uint8_t *key)
{
    uint32_t counter;

    counter = 0;
    return (gdbGet16(key, &counter) + KV_FORMAT_KLEN + KV_FORMAT_VLEN);
}

uint16_t keyGetrLenHs(const uint8_t *key)
{
    uint32_t counter;

    counter = KV_FORMAT_KLEN + KV_FORMAT_VLEN;
    return gdbGet16(key, &counter);
}

uint8_t keyGetcfLenHs(const uint8_t *key)
{
    uint32_t counter;

    counter = KV_FORMAT_KLEN + KV_FORMAT_VLEN + KV_FORMAT_RLEN + keyGetrLenHs(key);
    return gdbGet8(key, &counter);
}

uint16_t keyGetcqLenHs(const uint8_t *key)
{
    return (keyGetkLenHs(key)
         - keyGetrLenHs(key)
         - keyGetcfLenHs(key)
         - KV_FORMAT_RLEN
         - KV_FORMAT_CFLEN
         - KV_FORMAT_TSLEN
         - KV_FORMAT_TPLEN);
}

uint8_t keyGettsLenHs(const uint8_t *key)
{
    return (KV_FORMAT_TSLEN);
}

uint8_t keyGettpLenHs(const uint8_t *key)
{
    return (KV_FORMAT_TPLEN);
}

const uint8_t *keyGetRowHs(const uint8_t *key)
{
    return (key + KV_FORMAT_KLEN + KV_FORMAT_VLEN + KV_FORMAT_RLEN);
}

const uint8_t *keyGetColFamilyHs(const uint8_t *key)
{
    return (key + KV_FORMAT_KLEN + KV_FORMAT_VLEN + KV_FORMAT_RLEN + keyGetrLenHs(key) + KV_FORMAT_CFLEN);
}

const uint8_t *keyGetColQualifierHs(const uint8_t *key)
{
    return (key + KV_FORMAT_KLEN + KV_FORMAT_VLEN + KV_FORMAT_RLEN + keyGetrLenHs(key) + KV_FORMAT_CFLEN + keyGetcfLenHs(key));
}

ctime_t keyGetTimeStampHs(const uint8_t *key)
{
    uint32_t pos;
    pos = (KV_FORMAT_KLEN + KV_FORMAT_VLEN + keyGetkLenHs(key) - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN);
    return gdbGetTs(key, &pos);
}

uint8_t  keyGetType(const uint8_t *key)
{
    return *(key + KV_FORMAT_KLEN + KV_FORMAT_VLEN + keyGetkLenHs(key) - KV_FORMAT_TPLEN);
}


uint8_t *keyDupHs(const uint8_t *key, const word_t location)
{
    uint8_t *key_t;
    uint16_t len;

    len = keyGettLenHs(key);

    key_t = (uint8_t *)SAFE_MALLOC(len, location);
    if(NULL_PTR == key_t)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyDupHs: alloc %d bytes failed at %ld\n", len, location);
        return (NULL_PTR);
    }

    memcpy(key_t, key, len);
    return (key_t);
}

/*total length of key*/
uint16_t keyLenHs(const uint8_t *key)
{
    return keyGettLenHs(key);
}

uint8_t *keyNewHs(const uint16_t klen, const word_t location)
{
    uint8_t *key;

    key = (uint8_t *)SAFE_MALLOC(klen + KV_FORMAT_KLEN + KV_FORMAT_VLEN, location);
    if(NULL_PTR == key)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyNewHs:malloc %d bytes failed at %ld\n", klen + KV_FORMAT_KLEN + KV_FORMAT_VLEN, location);
        return NULL_PTR;
    }

    return (key);
}

void keyFreeHs(uint8_t *key, const word_t location)
{
    SAFE_FREE((void *)key, location);
    return;
}

STATIC_CAST static int _BCMP(const uint8_t *s1, const uint8_t *s2, size_t n)
{
    size_t pos;
    int result;
    sys_print(LOGSTDOUT, "\n");
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "_BCMP:s1: ");
    for(pos = 0; pos < n; pos ++)
    {
        sys_print(LOGSTDOUT, "%02x ", *(s1 + pos));
    }
    sys_print(LOGSTDOUT, "\n");

    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "_BCMP:s2: ");
    for(pos = 0; pos < n; pos ++)
    {
        sys_print(LOGSTDOUT, "%02x ", *(s2 + pos));
    }
    sys_print(LOGSTDOUT, "\n");

    result = BCMP(s1, s2, n);
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "compare result: %d\n", result);
    return result;
}

int  keyCmpHs(const uint8_t *key_1st, const uint8_t *key_2nd)
{
    uint16_t klen_1st;
    uint16_t klen_2nd;

    int cmp_result;

    klen_1st = keyGetkLenHs(key_1st);
    klen_2nd = keyGetkLenHs(key_2nd);

    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT,"keyCmpHs: [klen_1st %d, klen_2nd %d] ", klen_1st, klen_2nd);
    keyPrintHs(LOGSTDOUT, key_1st);
    sys_print(LOGSTDOUT," <----> ");
    keyPrintHs(LOGSTDOUT, key_2nd);

    cmp_result = BCMP(key_1st + KV_FORMAT_KLEN + KV_FORMAT_VLEN, key_2nd + KV_FORMAT_KLEN + KV_FORMAT_VLEN, DMIN(klen_1st, klen_2nd));
    if(0 != cmp_result)
    {
        sys_print(LOGSTDOUT," [0] %d\n", cmp_result);
        return cmp_result;
    }

    if(klen_1st < klen_2nd)
    {
        sys_print(LOGSTDOUT," [1] -1\n");
        return -1;
    }

    if(klen_1st > klen_2nd)
    {
        sys_print(LOGSTDOUT," [2] 1\n");
        return 1;
    }

    sys_print(LOGSTDOUT," [3] 0\n");
    return 0;
}

STATIC_CAST static int __mem_ncmp(uint8_t *src, const uint32_t slen, const uint8_t *des, const uint32_t dlen)
{
    uint32_t len;

    int result;

    len = DMIN(slen, dlen);
    result = BCMP(src, des, len);
    if(0 != result)
    {
        return (result);
    }

    if(slen < dlen)
    {
        return (-1);
    }

    if(slen > dlen)
    {
        return (1);
    }
    return (0);
}

int  keyCmpHs2(const uint8_t *key_1st, const uint8_t *key_2nd)
{
    uint16_t klen_1st;
    uint16_t rlen_1st;
    uint16_t cflen_1st;
  //  uint16_t olen_1st;/*other len, covering colq, ts, type*/
    uint16_t cqlen_1st;
    uint8_t *row_1st;
    uint8_t *colf_1st;
    uint8_t *colq_1st;
    //uint8_t *ostr_1st;

    uint16_t klen_2nd;
    uint16_t rlen_2nd;
    uint16_t cflen_2nd;
//    uint16_t olen_2nd;/*other len, covering colq, ts, type*/
    uint16_t cqlen_2nd;
    uint8_t *row_2nd;
    uint8_t *colf_2nd;
    uint8_t *colq_2nd;
    //uint8_t *ostr_2nd;

    uint32_t counter;
    int cmp_ret;
#if 0
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT,"keyCmpHs2: ");
    keyPrintHs(LOGSTDOUT, key_1st);
    sys_print(LOGSTDOUT," <----> ");
    keyPrintHs(LOGSTDOUT, key_2nd);
    sys_print(LOGSTDOUT, "\n");
#endif
    counter   = 0;
    klen_1st  = gdbGet16(key_1st, &counter);
    counter  += KV_FORMAT_VLEN;/*skip vlen*/
    rlen_1st  = gdbGet16(key_1st, &counter);
    row_1st   = (uint8_t *)(key_1st + counter);
    counter  += rlen_1st;/*skip row*/
    cflen_1st = gdbGet8(key_1st, &counter);
    colf_1st  = (uint8_t *)(key_1st + counter);
    counter  += cflen_1st;/*skip colf*/
    cqlen_1st = (klen_1st - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN) - (counter - KV_FORMAT_KLEN - KV_FORMAT_VLEN);
    colq_1st  = (uint8_t *)(key_1st + counter);
#if 0
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "keyCmpHs2: key_1st: klen_1st %d, row_1st %d (%.*s), colf_1st %d (%.*s), colq_1st %d (%.*s)\n",
                          klen_1st,
                          rlen_1st,  rlen_1st , row_1st,
                          cflen_1st, cflen_1st, colf_1st,
                          cqlen_1st, cqlen_1st, colq_1st
                          );
#endif
    counter = 0;
    klen_2nd = gdbGet16(key_2nd, &counter);
    counter += KV_FORMAT_VLEN;/*skip vlen*/
    rlen_2nd = gdbGet16(key_2nd, &counter);
    row_2nd = (uint8_t *)(key_2nd + counter);
    counter += rlen_2nd;/*skip row*/
    cflen_2nd = gdbGet8(key_2nd, &counter);
    colf_2nd = (uint8_t *)(key_2nd + counter);
    counter += cflen_2nd;/*skip colf*/
    cqlen_2nd = (klen_2nd - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN) - (counter - KV_FORMAT_KLEN - KV_FORMAT_VLEN);
    colq_2nd = (uint8_t *)(key_2nd + counter);
#if 0
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "keyCmpHs2: key_2nd: klen_2nd %d, row_2nd %d (%.*s), colf_2nd %d (%.*s), colq_2nd %d (%.*s)\n",
                          klen_2nd,
                          rlen_2nd,  rlen_2nd , row_2nd,
                          cflen_2nd, cflen_2nd, colf_2nd,
                          cqlen_2nd, cqlen_2nd, colq_2nd
                          );
#endif
    /*compare row*/
    cmp_ret = __mem_ncmp(row_1st, rlen_1st, row_2nd, rlen_2nd);
    cxReturnValueIf(cmp_ret, cmp_ret);

    /*compare colf*/
    cmp_ret = __mem_ncmp(colf_1st, cflen_1st, colf_2nd, cflen_2nd);
    cxReturnValueIf(cmp_ret, cmp_ret);

    /*compare colq*/
    cmp_ret = __mem_ncmp(colq_1st, cqlen_1st, colq_2nd, cqlen_2nd);
    cxReturnValueIf(cmp_ret, cmp_ret);

    return 0;
}

/*keyCmpHs3 is same as keyCmpHs2, for debug purpose only!*/
int  keyCmpHs3(const uint8_t *key_1st, const uint8_t *key_2nd)
{
    uint16_t klen_1st;
    uint16_t rlen_1st;
    uint16_t cflen_1st;
  //  uint16_t olen_1st;/*other len, covering colq, ts, type*/
    uint16_t cqlen_1st;
    uint8_t *row_1st;
    uint8_t *colf_1st;
    uint8_t *colq_1st;
    //uint8_t *ostr_1st;

    uint16_t klen_2nd;
    uint16_t rlen_2nd;
    uint16_t cflen_2nd;
//    uint16_t olen_2nd;/*other len, covering colq, ts, type*/
    uint16_t cqlen_2nd;
    uint8_t *row_2nd;
    uint8_t *colf_2nd;
    uint8_t *colq_2nd;
    //uint8_t *ostr_2nd;

    uint32_t counter;
    int cmp_ret;
#if 0
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT,"keyCmpHs3: ");
    keyPrintHs(LOGSTDOUT, key_1st);
    sys_print(LOGSTDOUT," <----> ");
    keyPrintHs(LOGSTDOUT, key_2nd);
    sys_print(LOGSTDOUT, "\n");
#endif
    counter   = 0;
    klen_1st  = gdbGet16(key_1st, &counter);
    counter  += KV_FORMAT_VLEN;/*skip vlen*/
    rlen_1st  = gdbGet16(key_1st, &counter);
    row_1st   = (uint8_t *)(key_1st + counter);
    counter  += rlen_1st;/*skip row*/
    cflen_1st = gdbGet8(key_1st, &counter);
    colf_1st  = (uint8_t *)(key_1st + counter);
    counter  += cflen_1st;/*skip colf*/
    cqlen_1st = (klen_1st - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN) - (counter - KV_FORMAT_KLEN - KV_FORMAT_VLEN);
    colq_1st  = (uint8_t *)(key_1st + counter);
#if 0
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "keyCmpHs3: key_1st: klen_1st %d, row_1st %d (%.*s), colf_1st %d (%.*s), colq_1st %d (%.*s)\n",
                          klen_1st,
                          rlen_1st,  rlen_1st , row_1st,
                          cflen_1st, cflen_1st, colf_1st,
                          cqlen_1st, cqlen_1st, colq_1st
                          );
#endif
    counter = 0;
    klen_2nd = gdbGet16(key_2nd, &counter);
    counter += KV_FORMAT_VLEN;/*skip vlen*/
    rlen_2nd = gdbGet16(key_2nd, &counter);
    row_2nd = (uint8_t *)(key_2nd + counter);
    counter += rlen_2nd;/*skip row*/
    cflen_2nd = gdbGet8(key_2nd, &counter);
    colf_2nd = (uint8_t *)(key_2nd + counter);
    counter += cflen_2nd;/*skip colf*/
    cqlen_2nd = (klen_2nd - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN) - (counter - KV_FORMAT_KLEN - KV_FORMAT_VLEN);
    colq_2nd = (uint8_t *)(key_2nd + counter);
#if 0
    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT, "keyCmpHs3: key_2nd: klen_2nd %d, row_2nd %d (%.*s), colf_2nd %d (%.*s), colq_2nd %d (%.*s)\n",
                          klen_2nd,
                          rlen_2nd,  rlen_2nd , row_2nd,
                          cflen_2nd, cflen_2nd, colf_2nd,
                          cqlen_2nd, cqlen_2nd, colq_2nd
                          );
#endif
    /*compare row*/
    cmp_ret = __mem_ncmp(row_1st, rlen_1st, row_2nd, rlen_2nd);
    cxReturnValueIf(cmp_ret, cmp_ret);

    /*compare colf*/
    cmp_ret = __mem_ncmp(colf_1st, cflen_1st, colf_2nd, cflen_2nd);
    cxReturnValueIf(cmp_ret, cmp_ret);

    /*compare colq*/
    cmp_ret = __mem_ncmp(colq_1st, cqlen_1st, colq_2nd, cqlen_2nd);
    cxReturnValueIf(cmp_ret, cmp_ret);

    return 0;
}

/*key of kv format: klen(2B) | vlen(4B) | rlen(2B) | row(rlen) | cflen(1B) | cf(cflen) | cq(cqlen) | ts(8B) | type(1B)*/
int  keyRegex(const uint8_t *key, pcre *row_re, pcre *colf_re, pcre *colq_re)
{
    uint16_t klen;
    uint16_t rlen;
    uint16_t cflen;
    uint16_t cqlen;/*other len, covering colq, ts, type*/
    uint8_t *row;
    uint8_t *colf;
    uint8_t *colq;

    uint32_t counter;

    int ovec[3];
    int ovec_count;

    counter = 0;
    klen = gdbGet16(key, &counter);
    counter += KV_FORMAT_VLEN;/*skip vlen*/
    rlen = gdbGet16(key, &counter);
    row = (uint8_t *)(key + counter);
    counter += rlen;/*skip row*/
    cflen = gdbGet8(key, &counter);
    colf = (uint8_t *)(key + counter);
    counter += cflen;/*skip colf*/
    colq = (uint8_t *)(key + counter);
    cqlen = klen - rlen - cflen - KV_FORMAT_RLEN - KV_FORMAT_CFLEN - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN;

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    if(NULL_PTR != row_re && 0 > pcre_exec(row_re, NULL_PTR, (char *)row, rlen, 0, 0, ovec, ovec_count))
    {
        //dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: row not matched where row is %.*s\n", rlen, row);
        return 0;/*fail*/
    }

    if(NULL_PTR != colf_re && 0 > pcre_exec(colf_re, NULL_PTR, (char *)colf, cflen, 0, 0, ovec, ovec_count))
    {
        //dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: colf not matched where colf is %.*s\n", cflen, colf);
        return 0;/*fail*/
    }

    if(NULL_PTR != colq_re && 0 > pcre_exec(colq_re, NULL_PTR, (char *)colq, cqlen, 0, 0, ovec, ovec_count))
    {
        //dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: colq not matched where colq is %.*s\n", cqlen, colq);
        return 0;/*fail*/
    }

    return 1;/*succ*/
}

void keyPrintHs(LOG *log, const uint8_t *key)
{
    uint16_t klen;
    uint16_t rlen;
    uint32_t vlen;
    uint16_t cqlen;
    uint8_t  cflen;
    uint8_t  type;

    uint8_t *row;
    uint8_t *col_family;
    uint8_t *col_qualifier;
    ctime_t  time_stamp;

    uint32_t counter;
    uint32_t pos;

    sys_print(log,"(%lx,", key);

    counter = 0;
    klen = gdbGet16(key, &counter);
    //sys_print(log,"klen %d,", klen);

    vlen = gdbGet32(key, &counter);
    //sys_print(log,"vlen %d,",vlen);

    cxGotoUnless(klen >= KV_FORMAT_RLEN, __last);
    rlen = gdbGet16(key, &counter);
    //sys_print(log,"rlen %d,",rlen);
    klen -= KV_FORMAT_RLEN;

    cxGotoUnless(klen >= rlen, __last);
    row  = (uint8_t *)key + counter;
    __print_kv_chars(log, row, rlen);
    //sys_print(log,"%.*s:", rlen, row);
    sys_print(log, ":");
    klen -= rlen;

    counter += rlen;

    cxGotoUnless(klen >= KV_FORMAT_CFLEN, __last);
    cflen = gdbGet8(key, &counter);
    //sys_print(log,"cflen %d,", cflen);
    klen -= KV_FORMAT_CFLEN;

    cxGotoUnless(klen >= cflen, __last);
    col_family = (uint8_t *)key + counter;
    //sys_print(log,"%.*s:", cflen, col_family);
    __print_kv_chars(log, col_family, cflen);
    sys_print(log, ":");
    klen -= cflen;

    counter += cflen;

    cxGotoUnless(klen > KV_FORMAT_TSLEN + KV_FORMAT_TPLEN, __last);
    col_qualifier = (uint8_t *)key + counter;
    //cqlen = klen - 2 - rlen - 1 - cflen - 8 - 1;
    cqlen = klen - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN;
    //sys_print(log,"cqlen %d,", cqlen);
    //sys_print(log,"%.*s:", cqlen, col_qualifier);
    __print_kv_chars(log, col_qualifier, cqlen);
    sys_print(log, ":");

    counter += cqlen;

    pos = counter;
    time_stamp = gdbGetTs(key, &pos);
    sys_print(log, "%ld", time_stamp);
    //__print_kv_chars(log, time_stamp, KV_FORMAT_TSLEN);
    sys_print(log, ":");

    counter += KV_FORMAT_TSLEN;
    type = gdbGet8(key, &counter);

    sys_print(log, "%d", type);

__last:
    sys_print(log, ")");
}

KeyValue *keyValueNewHs(const uint32_t vlen,
                      const uint16_t rlen, const uint8_t *row,
                      const uint8_t  cflen, const uint8_t *col_family,
                      const uint16_t cqlen, const uint8_t *col_qualifier,
                      const ctime_t  time_stamp,
                      const uint8_t  type,
                      const uint8_t *value,
                      const word_t location)
{
    KeyValue *keyValue;

    keyValue = (KeyValue *)SAFE_MALLOC(sizeof(KeyValue), location);
    if(NULL_PTR == keyValue)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyValueNewHs:malloc KeyValue failed at %ld\n", location);
        return NULL_PTR;
    }
    BSET(keyValue, 0, sizeof(KeyValue));

    keyValueSetHs(keyValue, vlen, rlen, row, cflen, col_family, cqlen, col_qualifier, time_stamp, type, value, location);
    return keyValue;
}

/*not dup anything*/
KeyValue *keyValueMakeHs(const uint32_t vlen,
                      const uint16_t rlen, const uint8_t *row,
                      const uint8_t  cflen, const uint8_t *col_family,
                      const uint16_t cqlen, const uint8_t *col_qualifier,
                      const ctime_t time_stamp,
                      const uint8_t  type,
                      const uint8_t *value,
                      const word_t location)
{
    KeyValue *keyValue;

    keyValue = (KeyValue *)SAFE_MALLOC(sizeof(KeyValue), location);
    if(NULL_PTR == keyValue)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:keyValueNewHs:malloc KeyValue failed at %ld\n", location);
        return NULL_PTR;
    }
    BSET(keyValue, 0, sizeof(KeyValue));

    keyValueInitHs(keyValue, vlen, rlen, row, cflen, col_family, cqlen, col_qualifier, time_stamp, type, value);
    return keyValue;
}

void keyValueUnMakeHs(KeyValue *keyValue, const word_t location)
{
    if(keyValue)
    {
        SAFE_FREE(keyValue, location);
    }
    return;
}

void keyValueCleanHs(KeyValue *keyValue, const word_t location)
{
    if(keyValue->row)
    {
        SAFE_FREE(keyValue->row, location);
        keyValue->row = NULL_PTR;
    }

    if(keyValue->col_family)
    {
        SAFE_FREE(keyValue->col_family, location);
        keyValue->col_family = NULL_PTR;
    }

    if(keyValue->col_qualifier)
    {
        SAFE_FREE(keyValue->col_qualifier, location);
        keyValue->col_qualifier = NULL_PTR;
    }

    keyValue->time_stamp = 0;

    if(keyValue->value)
    {
        SAFE_FREE(keyValue->value, location);
        keyValue->value = NULL_PTR;
    }
    return;
}

void keyValueFreeHs(KeyValue *keyValue, const word_t location)
{
    if(keyValue)
    {
        keyValueCleanHs(keyValue, location);
        SAFE_FREE(keyValue, location);
    }
    return;
}

void keyValueInitHs(KeyValue *keyValue, const uint32_t vlen,
                              const uint16_t rlen, const uint8_t *row,
                              const uint8_t  cflen, const uint8_t *col_family,
                              const uint16_t cqlen, const uint8_t *col_qualifier,
                              const ctime_t  time_stamp,
                              const uint8_t  type,
                              const uint8_t *value)
{
    keyValue->klen  = KV_FORMAT_RLEN + rlen + KV_FORMAT_CFLEN + cflen + cqlen + KV_FORMAT_TSLEN + KV_FORMAT_TPLEN;
    keyValue->rlen  = rlen;
    keyValue->vlen  = vlen;
    keyValue->cqlen = cqlen;
    keyValue->cflen = cflen;
    keyValue->type  = type;

    keyValue->row           = (uint8_t *)row;
    keyValue->col_family    = (uint8_t *)col_family;
    keyValue->col_qualifier = (uint8_t *)col_qualifier;
    keyValue->time_stamp    = time_stamp;
    keyValue->value         = (uint8_t *)value;

    return;
}

void keyValueSetHs(KeyValue *keyValue, const uint32_t vlen,
                              const uint16_t rlen, const uint8_t *row,
                              const uint8_t  cflen, const uint8_t *col_family,
                              const uint16_t cqlen, const uint8_t *col_qualifier,
                              const ctime_t  time_stamp,
                              const uint8_t  type,
                              const uint8_t *value,
                              const word_t location)
{
    keyValue->klen  = 0;
    keyValue->rlen  = rlen;
    keyValue->vlen  = vlen;
    keyValue->cqlen = cqlen;
    keyValue->cflen = cflen;
    keyValue->type  = type;

    MEM_CHECK(keyValue->row           = (uint8_t *)SAFE_MALLOC(rlen , LOC_KEYVALUE_0001));
    BCOPY(row          , keyValue->row          , rlen );
    keyValue->klen += KV_FORMAT_RLEN + rlen;

    cxReturnUnless(0 != cflen && NULL_PTR != col_family);
    MEM_CHECK(keyValue->col_family    = (uint8_t *)SAFE_MALLOC(cflen, LOC_KEYVALUE_0002));
    BCOPY(col_family   , keyValue->col_family   , cflen);
    keyValue->klen += 1 + cflen;

    cxReturnUnless(0 != cqlen && NULL_PTR != col_qualifier);
    MEM_CHECK(keyValue->col_qualifier = (uint8_t *)SAFE_MALLOC(cqlen, LOC_KEYVALUE_0003));
    BCOPY(col_qualifier, keyValue->col_qualifier, cqlen);
    keyValue->klen += cqlen;

    //cxReturnUnless(NULL_PTR != time_stamp);
    keyValue->time_stamp = time_stamp;
    keyValue->klen += KV_FORMAT_TSLEN;

    cxReturnUnless(KEY_TYPE_IS_ERR != type);
    keyValue->klen += 1;

    cxReturnUnless(0 != vlen && NULL_PTR != value);
    MEM_CHECK(keyValue->value         = (uint8_t *)SAFE_MALLOC(vlen , LOC_KEYVALUE_0004));
    BCOPY(value        , keyValue->value        , vlen );

    return;
}

void keyValuePutKeyHs(uint8_t *buffer, const KeyValue *keyValue)
{
    uint32_t counter;

    counter = 0;
    gdbPut16(buffer, &counter, keyValue->klen);
    gdbPut32(buffer, &counter, keyValue->vlen);
    gdbPut16(buffer, &counter, keyValue->rlen);
    gdbPut8s(buffer, &counter, keyValue->row, keyValue->rlen);

    cxReturnUnless(0 != keyValue->cflen && NULL_PTR != keyValue->col_family);
    gdbPut8 (buffer, &counter, keyValue->cflen);
    gdbPut8s(buffer, &counter, keyValue->col_family, keyValue->cflen);

    cxReturnUnless(0 != keyValue->cqlen && NULL_PTR != keyValue->col_qualifier);
    gdbPut8s(buffer, &counter, keyValue->col_qualifier, keyValue->cqlen);

    gdbPutTs(buffer, &counter, keyValue->time_stamp);

    cxReturnUnless(KEY_TYPE_IS_ERR != keyValue->type);
    gdbPut8 (buffer, &counter, keyValue->type);
    return;
}

KeyValue *keyValueGetKeyHs(uint8_t *buffer, const word_t location)
{
    uint32_t counter;
    uint16_t klen;
    uint16_t rlen;
    uint32_t vlen;
    uint16_t cqlen;
    uint8_t  cflen;
    uint8_t  type;

    uint8_t *row;
    uint8_t *col_family;
    uint8_t *col_qualifier;
    ctime_t  time_stamp;
    uint32_t pos;
    //uint8_t *value;

    counter = 0;
    klen = gdbGet16(buffer, &counter);
    vlen = gdbGet32(buffer, &counter);
    rlen = gdbGet16(buffer, &counter);
    row  = buffer + counter;
    counter += rlen;

    cflen = gdbGet8(buffer, &counter);
    col_family = buffer + counter;
    counter += cflen;

    col_qualifier = buffer + counter;
    cqlen = klen - KV_FORMAT_RLEN - rlen - KV_FORMAT_CFLEN - cflen - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN;
    counter += cqlen;

    pos = counter;
    time_stamp = gdbGetTs(buffer, &pos);
    ASSERT(KV_FORMAT_TSLEN == pos - counter);
    counter += KV_FORMAT_TSLEN;
    type = gdbGet8(buffer, &counter);

    return keyValueNewHs(vlen,
                   rlen, row,
                   cflen, col_family,
                   cqlen, col_qualifier,
                   time_stamp,
                   type,
                   NULL_PTR,
                   location);
}

void keyValueSetValueHs(KeyValue *keyValue, const uint8_t *value)
{
    keyValue->value = (uint8_t *)value;
    return;
}

void keyValuePutHs(uint8_t *buffer, const KeyValue *keyValue)
{
    uint32_t counter;
    uint32_t pos;

    counter = 0;
    gdbPut16(buffer, &counter, keyValue->klen);
    gdbPut32(buffer, &counter, keyValue->vlen);

    gdbPut16(buffer, &counter, keyValue->rlen);
    gdbPut8s(buffer, &counter, keyValue->row, keyValue->rlen);

    cxReturnUnless(0 != keyValue->cflen && NULL_PTR != keyValue->col_family);
    gdbPut8 (buffer, &counter, keyValue->cflen);
    gdbPut8s(buffer, &counter, keyValue->col_family, keyValue->cflen);

    cxReturnUnless(0 != keyValue->cqlen && NULL_PTR != keyValue->col_qualifier);
    gdbPut8s(buffer, &counter, keyValue->col_qualifier, keyValue->cqlen);

    pos = counter;
    gdbPutTs(buffer, &pos, keyValue->time_stamp);
    ASSERT(KV_FORMAT_TSLEN == pos - counter);
    counter += KV_FORMAT_TSLEN;

    cxReturnUnless(KEY_TYPE_IS_ERR != keyValue->type);
    gdbPut8 (buffer, &counter, keyValue->type);

    cxReturnUnless(0 != keyValue->vlen && NULL_PTR != keyValue->value);
    gdbPut8s(buffer, &counter, keyValue->value, keyValue->vlen);
    return;
}

uint16_t keyValueGetkLenHs(const KeyValue *keyValue)
{
    return (keyValue->klen);
}

uint32_t keyValueGetvLenHs(const KeyValue *keyValue)
{
    return (keyValue->vlen);
}

/*total keyValue length: sizeof(klen) + sizeof(vlen) + klen = 2 + 4 + klen = 6 + klen*/
uint16_t keyValueGettLenHs(const KeyValue *keyValue)
{
    return (KV_FORMAT_KLEN + KV_FORMAT_VLEN + keyValue->klen + keyValue->vlen);
}

uint16_t keyValueGetrLenHs(const KeyValue *keyValue)
{
    return (keyValue->rlen);
}

uint8_t keyValueGetcfLenHs(const KeyValue *keyValue)
{
    return (keyValue->cflen);
}

uint16_t keyValueGetcqLenHs(const KeyValue *keyValue)
{
    return (keyValueGetkLenHs(keyValue)
         - keyValueGetrLenHs(keyValue)
         - keyValueGetcfLenHs(keyValue)
         - KV_FORMAT_RLEN
         - KV_FORMAT_CFLEN
         - KV_FORMAT_TSLEN
         - KV_FORMAT_TPLEN);
}

uint8_t keyValueGettsLenHs(const KeyValue *keyValue)
{
    return (KV_FORMAT_TSLEN);
}

uint8_t keyValueGettpLenHs(const KeyValue *keyValue)
{
    return (KV_FORMAT_TPLEN);
}

void keyValuePrintHs(LOG *log, const KeyValue *keyValue)
{
    sys_log(log,"klen    = %d\n", keyValue->klen);
    sys_log(log,"rlen    = %d, row = %.*s\n", keyValue->rlen, keyValue->rlen, keyValue->row);
    sys_log(log,"vlen    = %d, val = %.*s\n", keyValue->vlen, keyValue->vlen, keyValue->value);
    sys_log(log,"cflen   = %d, cf  = %.*s\n", keyValue->cflen, keyValue->cflen, keyValue->col_family);
    sys_log(log,"cqlen   = %d, cq  = %.*s\n", keyValue->cqlen, keyValue->cqlen, keyValue->col_qualifier);
    sys_log(log,"ts      = %ld\n", keyValue->time_stamp);
    sys_log(log,"type    = %d\n", keyValue->type);
}


uint8_t *kvNewHs(const KeyValue *keyValue, const word_t location)
{
    uint8_t *kv;
    uint16_t len;

    len = keyValueGettLenHs(keyValue);

    kv = (uint8_t *)SAFE_MALLOC(len, location);
    if(NULL_PTR == keyValue)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:kvNewHs:malloc %d bytes failed at %ld\n", len, location);
        return NULL_PTR;
    }
    BSET(kv, 0, len);

    return kv;
}

uint8_t *kvNewHs2(const uint16_t tlen, const word_t location)
{
    uint8_t *kv;

    kv = (uint8_t *)SAFE_MALLOC(tlen, location);
    if(NULL_PTR == kv)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:kvNewHs2:malloc %d bytes failed at %ld\n", tlen, location);
        return NULL_PTR;
    }
    return (kv);
}

void kvPutHs(uint8_t *kv, const KeyValue *keyValue)
{
    keyValuePutHs(kv, keyValue);
    return;
}

void kvFreeHs(uint8_t *kv, const word_t location)
{
    SAFE_FREE(kv, location);
    return;
}

void kvPrintHs(LOG *log, const uint8_t *kv)
{
    const uint8_t *key;
    const uint8_t *val;
    uint32_t vlen;

    key  = kv;
    val  = kvGetValueHs(kv);
    vlen = kvGetvLenHs(kv);

    sys_print(log,"key = ");
    keyPrintHs(log, key);
    sys_print(log," ");
    sys_print(log,"val = ");
    __print_kv_chars(log, val, vlen);
    //sys_log(log,"val = %.*s (vlen = %d)\n", vlen, val, vlen);
    sys_print(log, "\n");
    return;
}

/*if kv_2nd is the start substring kv_1st, then matched and return 0, otherwise return the compare result*/
int kvMatchHs(const uint8_t *kv_1st, const uint8_t *kv_2nd)
{
    uint16_t klen_1st;
    uint16_t klen_2nd;

    int cmp_result;

    klen_1st = keyGetkLenHs(kv_1st);
    klen_2nd = keyGetkLenHs(kv_2nd);

    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT,"kvMatchHs: [klen_1st %d, klen_2nd %d] ", klen_1st, klen_2nd);
    keyPrintHs(LOGSTDOUT, kv_1st);
    sys_print(LOGSTDOUT," <----> ");
    keyPrintHs(LOGSTDOUT, kv_2nd);

    if(klen_1st >= klen_2nd)
    {
        cmp_result = BCMP(kv_1st + KV_FORMAT_KLEN + KV_FORMAT_VLEN, kv_2nd + KV_FORMAT_KLEN + KV_FORMAT_VLEN, klen_2nd - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN);
        sys_print(LOGSTDOUT," [0] %d\n", cmp_result);
        return cmp_result;
    }

    cmp_result = BCMP(kv_1st + KV_FORMAT_KLEN + KV_FORMAT_VLEN, kv_2nd + KV_FORMAT_KLEN + KV_FORMAT_VLEN, klen_1st - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN);
    if( 0 == cmp_result)
    {
        sys_print(LOGSTDOUT," [1] -1\n");
        return -1;
    }

    sys_print(LOGSTDOUT," [2] %d\n", cmp_result);
    return cmp_result;
}

/*if kv_1st >= kv_2nd, return 0, else return 1*/
int kvGtHs(const uint8_t *kv_1st, const uint8_t *kv_2nd)
{
    uint16_t klen_1st;
    uint16_t klen_2nd;

    int cmp_result;

    klen_1st = keyGetkLenHs(kv_1st);
    klen_2nd = keyGetkLenHs(kv_2nd);

    dbg_log(SEC_0133_KEYVALUE, 5)(LOGSTDOUT,"kvGtHs: [klen_1st %d, klen_2nd %d] ", klen_1st, klen_2nd);
    keyPrintHs(LOGSTDOUT, kv_1st);
    sys_print(LOGSTDOUT," <----> ");
    keyPrintHs(LOGSTDOUT, kv_2nd);

    if(klen_1st >= klen_2nd)
    {
        cmp_result = BCMP(kv_1st + KV_FORMAT_KLEN + KV_FORMAT_VLEN, kv_2nd + KV_FORMAT_KLEN + KV_FORMAT_VLEN, klen_2nd - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN);
        if(0 <= cmp_result)/*kv_1st >= kv_2nd*/
        {
            sys_print(LOGSTDOUT," [0] 0\n");
            return 0;
        }
        sys_print(LOGSTDOUT," [1] 1\n");
        return 1;
    }

    cmp_result = BCMP(kv_1st + KV_FORMAT_KLEN + KV_FORMAT_VLEN, kv_2nd + KV_FORMAT_KLEN + KV_FORMAT_VLEN, klen_1st - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN);
    if( 0 == cmp_result || 0 > cmp_result)
    {
        sys_print(LOGSTDOUT," [2] 1\n");
        return 1;
    }

    sys_print(LOGSTDOUT," [3] 0\n");
    return 0;
}

uint16_t kvGetkLenHs(const uint8_t *kv)
{
    return keyGetkLenHs(kv);
}

uint32_t kvGetvLenHs(const uint8_t *kv)
{
    return keyGetvLenHs(kv);
}

/*total kv length: sizeof(klen) + sizeof(vlen) + klen + vlen*/
uint32_t kvGettLenHs(const uint8_t *kv)
{
    return keyGettLenHs(kv) + keyGetvLenHs(kv);
}

uint16_t kvGetrLenHs(const uint8_t *kv)
{
    return keyGetrLenHs(kv);
}

uint8_t kvGetcfLenHs(const uint8_t *kv)
{
    return keyGetcfLenHs(kv);
}

uint16_t kvGetcqLenHs(const uint8_t *kv)
{
    return keyGetcqLenHs(kv);
}

uint8_t kvGettsLenHs(const uint8_t *kv)
{
    return keyGettsLenHs(kv);
}

uint8_t kvGettpLenHs(const uint8_t *kv)
{
    return keyGettpLenHs(kv);
}

const uint8_t *kvGetRowHs(const uint8_t *kv)
{
    return keyGetRowHs(kv);
}

const uint8_t *kvGetColFamilyHs(const uint8_t *kv)
{
    return keyGetColFamilyHs(kv);
}

const uint8_t *kvGetColQualifierHs(const uint8_t *kv)
{
    return keyGetColQualifierHs(kv);
}

ctime_t kvGetTimeStampHs(const uint8_t *kv)
{
    return keyGetTimeStampHs(kv);
}

uint8_t kvGetTypeHs(const uint8_t *kv)
{
    return keyGetType(kv);
}

const uint8_t *kvGetValueHs(const uint8_t *kv)
{
    return (kv + KV_FORMAT_KLEN + KV_FORMAT_VLEN + kvGetkLenHs(kv));
}

uint8_t *kvDupHs(const uint8_t *kv, const word_t location)
{
    uint8_t *kv_t;
    uint16_t len;

    len = kvGettLenHs(kv);

    kv_t = (uint8_t *)SAFE_MALLOC(len, location);
    if(NULL_PTR == kv_t)
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT,"error:kvDupHs: alloc %d bytes failed at %ld\n", len, location);
        return (NULL_PTR);
    }

    BCOPY(kv, kv_t, len);
    return (kv_t);
}

int  kvCmpKeyHs(const uint8_t *kv_1st, const uint8_t *kv_2nd)
{
    return keyCmpHs2(kv_1st, kv_2nd);
}

STATIC_CAST static void __kvSplitRowkeyScope(const uint8_t *rowkey_scope, uint8_t **start_rowkey, uint8_t **end_rowkey)
{
    (*start_rowkey) = (uint8_t *)(rowkey_scope);
    (*end_rowkey)   = (uint8_t *)(rowkey_scope + keyGettLenHs(rowkey_scope));
    return;
}

/**
*
*   scope_1st = (s1, e1], scope_2nd = (s2, e2], scope_1st and scope_2nd has no intersection
*   thus,
*     if s1 >= e2, then scope_1st > scope_2nd
*     else if e1 <= s2, then scope_1st < scope_2nd
*     else  scope_1st = scope_2nd
*
*   warning: if scope_2nd = (e1, e1], what will happen?
*
**/
STATIC_CAST static int __kvCmpRowInRowkeyScope(const uint8_t *rowkey_scope_1st, const uint8_t *rowkey_scope_2nd)
{
    uint8_t *start_rowkey_1st;
    uint8_t *end_rowkey_1st;
    uint8_t *start_rowkey_2nd;
    uint8_t *end_rowkey_2nd;

    int cmp_ret;

    __kvSplitRowkeyScope(rowkey_scope_1st, &start_rowkey_1st, &end_rowkey_1st);
    __kvSplitRowkeyScope(rowkey_scope_2nd, &start_rowkey_2nd, &end_rowkey_2nd);

    cmp_ret = keyCmpHs3(start_rowkey_1st, end_rowkey_2nd);
    if(0 <= cmp_ret)/*i.e., rowkey_scope_2nd < rowkey_scope_1st, rowkey_scope_2nd is the left scope of rowkey_scope_1st*/
    {
        return (1);
    }

    cmp_ret = keyCmpHs3(end_rowkey_1st, start_rowkey_2nd);
    if(0 >= cmp_ret)
    {
        return (-1);
    }

    /*i.e., rowkey_scope_2nd belong to rowkey_scope_1st, rowkey_scope_2nd is the sub scope of rowkey_scope_1st*/
    return (0);
}

int  kvCmpRowkeyScopeHs(const uint8_t *kv_1st, const uint8_t *kv_2nd)
{
    const uint8_t *rowkey_scope_1st;
    const uint8_t *rowkey_scope_2nd;

    rowkey_scope_1st = keyGetRowHs(kv_1st);
    rowkey_scope_2nd = keyGetRowHs(kv_2nd);

    return __kvCmpRowInRowkeyScope(rowkey_scope_1st, rowkey_scope_2nd);
}

EC_BOOL kvEncodeSize(const uint8_t *kv, uint32_t *size)
{
    (*size) += kvGettLenHs(kv);
    return (EC_TRUE);
}

EC_BOOL kvEncode(const uint8_t *kv, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint32_t len;

    len = kvGettLenHs(kv);
    if(len > size - (*pos))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT, "error:kvEncode: left room is %d bytes, no enough room to accept %d bytes\n",
                            size - (*pos), len);
        return (EC_FALSE);
    }

    gdbPut8s(buff, pos, kv, len);
    return (EC_TRUE);
}

EC_BOOL kvDecode(uint8_t **kv, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint16_t klen;
    uint32_t vlen;
    uint32_t tlen;

    if(KV_FORMAT_KLEN + KV_FORMAT_VLEN > size - (*pos))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT, "error:kvDecode: left room is %d bytes, insufficient to decode klen,vlen info\n",
                            size - (*pos));
        return (EC_FALSE);
    }

    klen = gdbGet16(buff, pos);/*2B i.e. KV_FORMAT_KLEN*/
    vlen = gdbGet32(buff, pos);/*4B i.e. KV_FORMAT_VLEN*/
    tlen = klen + vlen + KV_FORMAT_KLEN + KV_FORMAT_VLEN;

    (*pos) -= KV_FORMAT_KLEN + KV_FORMAT_VLEN;/*roll back*/

    if(tlen > size - (*pos))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT, "error:kvDecode: left room is %d bytes, insufficient to decode kv with klen %d and vlen %d\n",
                            size - (*pos), klen, vlen);
        return (EC_FALSE);
    }

    (*kv) = (uint8_t *)safe_malloc(tlen, LOC_KEYVALUE_0005);
    if(NULL_PTR == (*kv))
    {
        dbg_log(SEC_0133_KEYVALUE, 0)(LOGSTDOUT, "error:kvDecode: malloc %d bytes failed\n", tlen);
        return (EC_FALSE);
    }

    gdbGet8s(buff, pos, (*kv), tlen);
    return (EC_TRUE);
}


/*format: klen(2B) | vlen(4B) | rlen(2B) | row(rlen) | cflen(1B) | cf(cflen) | cq(cqlen) | ts(8B) | type(1B) | val(vlen)*/
int  kvRegex(const uint8_t *key, pcre *row_re, pcre *colf_re, pcre *colq_re, pcre *val_re)
{
    uint16_t klen;
    uint16_t rlen;
    uint16_t cflen;
    uint16_t cqlen;/*other len, covering colq, ts, type*/
    uint32_t vlen;
    uint8_t *row;
    uint8_t *colf;
    uint8_t *colq;
    uint8_t *val;

    uint32_t counter;

    int ovec[3];
    int ovec_count;

    counter = 0;
    klen = gdbGet16(key, &counter);
    vlen = gdbGet32(key, &counter);
    rlen = gdbGet16(key, &counter);
    row = (uint8_t *)(key + counter);
    counter += rlen;/*skip row*/
    cflen = gdbGet8(key, &counter);
    colf = (uint8_t *)(key + counter);
    counter += cflen;/*skip colf*/
    colq = (uint8_t *)(key + counter);
    cqlen = klen - rlen - cflen - KV_FORMAT_RLEN - KV_FORMAT_CFLEN - KV_FORMAT_TSLEN - KV_FORMAT_TPLEN;
    counter += cqlen;/*skip colq*/
    counter += KV_FORMAT_TSLEN; /*skip ts*/
    counter += KV_FORMAT_TPLEN; /*skip type*/
    val = (uint8_t *)(key + counter);

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    if(NULL_PTR != row_re && 0 > pcre_exec(row_re, NULL_PTR, (char *)row, rlen, 0, 0, ovec, ovec_count))
    {
        dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: row not matched where row is %.*s\n", rlen, row);
        return 0;/*fail*/
    }

    if(NULL_PTR != colf_re && 0 > pcre_exec(colf_re, NULL_PTR, (char *)colf, cflen, 0, 0, ovec, ovec_count))
    {
        dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: colf not matched where colf is %.*s\n", cflen, colf);
        return 0;/*fail*/
    }

    if(NULL_PTR != colq_re && 0 > pcre_exec(colq_re, NULL_PTR, (char *)colq, cqlen, 0, 0, ovec, ovec_count))
    {
        dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: colq not matched where colq is %.*s\n", cqlen, colq);
        return 0;/*fail*/
    }

    if(NULL_PTR != val_re && 0 > pcre_exec(val_re, NULL_PTR, (char *)val, vlen, 0, 0, ovec, ovec_count))
    {
        dbg_log(SEC_0133_KEYVALUE, 9)(LOGSTDOUT, "[DEBUG] keyRegex: val not matched where val is %.*s\n", vlen, val);
        return 0;/*fail*/
    }

    return 1;/*succ*/
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

