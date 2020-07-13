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

#ifndef _CSTRING_H
#define _CSTRING_H

#include "type.h"
#include "cbytes.h"
#include "cvector.h"

#define CSTRING_MIN_CAPACITY (128)

#define CSTRING_OVEC_SEGS    (10)
#define CSTRING_OVEC_COUNT   (3 * CSTRING_OVEC_SEGS)


CSTRING *cstring_new(const UINT8 *str, const UINT32 location);
CSTRING *cstring_new_0();

void cstring_free(CSTRING *cstring);
void cstring_free_1(CSTRING *cstring, const UINT32 location);

void cstring_init(CSTRING *cstring, const UINT8 *str);

void cstring_init_0(CSTRING *cstring);

void cstring_clean(CSTRING *cstring);

void cstring_reset(CSTRING *cstring);

void cstring_clone(const CSTRING *cstring_src, CSTRING *cstring_des);

EC_BOOL cstring_clone_0(const CSTRING *cstring_src, CSTRING *cstring_des);

EC_BOOL cstring_empty(CSTRING *cstring);

EC_BOOL cstring_is_empty(const CSTRING *cstring);

EC_BOOL cstring_is_str(const CSTRING *cstring_src, const UINT8 *str);

EC_BOOL cstring_is_str_ignore_case(const CSTRING *cstring_src, const UINT8 *str);

EC_BOOL cstring_is_equal_ignore_case(const CSTRING *cstring_src, const CSTRING *cstring_des);

EC_BOOL cstring_is_equal(const CSTRING *cstring_src, const CSTRING *cstring_des);

EC_BOOL cstring_is_equal_n(const CSTRING *cstring_src, const CSTRING *cstring_des, const UINT32 n);

int cstring_cmp(const CSTRING *cstring_src, const CSTRING *cstring_des);

int cstring_cmp_ignore_case(const CSTRING *cstring_src, const CSTRING *cstring_des);

int cstring_ocmp(const CSTRING *cstring_src, const CSTRING *cstring_des);

int cstring_ncmp(const CSTRING *cstring_src, const CSTRING *cstring_des, const UINT32 n);

EC_BOOL cstring_expand(CSTRING *cstring, const UINT32 location);

EC_BOOL cstring_expand_to(CSTRING *cstring, const UINT32 size, const UINT32 location);

EC_BOOL cstring_set_capacity(CSTRING *cstring, const UINT32 capacity);

UINT32 cstring_get_capacity(const CSTRING *cstring);

UINT32 cstring_get_len(const CSTRING *cstring);

UINT32 cstring_get_room(const CSTRING *cstring);

UINT8 * cstring_get_str(const CSTRING *cstring);

EC_BOOL cstring_get_char(const CSTRING *cstring, const UINT32 pos, UINT8 *pch);

EC_BOOL cstring_set_word(CSTRING *cstring, const UINT32 num);

UINT32 cstring_get_word(const CSTRING *cstring);

EC_BOOL cstring_set_str(CSTRING *cstring, const UINT8 *str);

EC_BOOL cstring_unset(CSTRING *cstring);

EC_BOOL cstring_set_char(CSTRING *cstring, const UINT8 ch, const UINT32 pos);

CBYTES *cstring_get_cbytes(const CSTRING *cstring);

EC_BOOL cstring_get_cstr(const CSTRING *cstring_src, const UINT32 from, const UINT32 to, CSTRING *cstring_des);

EC_BOOL cstring_set_chars(CSTRING *cstring, const UINT8 *pchs, const UINT32 len);

CSTRING *cstring_make(const char *format, ...);

CSTRING *cstring_make_by_word(const UINT32 num);

CSTRING *cstring_make_by_ctimet(const CTIMET *ctimet);

CSTRING *cstring_make_by_bytes(const UINT32 len, const UINT8 *bytes);

CSTRING *cstring_dup(const CSTRING *cstring_src);

EC_BOOL cstring_erase_char(CSTRING *cstring, const UINT32 pos);

EC_BOOL cstring_append_char(CSTRING *cstring, const UINT8 ch);

EC_BOOL cstring_append_chars(CSTRING *cstring, const UINT32 ch_num, const UINT8 *chars, const UINT32 location);

EC_BOOL cstring_append_str(CSTRING *cstring, const UINT8 *str);

EC_BOOL cstring_append_cstr(CSTRING *cstring_des, const CSTRING *cstring_src);

EC_BOOL cstring_erase_sub_str(CSTRING *cstring, const UINT32 from, const UINT32 to);

EC_BOOL cstring_erase_tail_str(CSTRING *cstring, const UINT32 len);

EC_BOOL cstring_erase_tail_until(CSTRING *cstring, const UINT8 ch);

EC_BOOL cstring_ltrim(CSTRING *cstring, const UINT8 ch);

EC_BOOL cstring_rtrim(CSTRING *cstring, const UINT8 ch);

EC_BOOL cstring_trim(CSTRING *cstring, const UINT8 ch);

/*read content from fp and write into cstring*/
UINT32 cstring_fread(CSTRING *cstring, FILE *fp);

void cstring_print(LOG *log, const CSTRING *cstring);

EC_BOOL cstring_format(CSTRING *cstring, const char *format, ...);

EC_BOOL cstring_vformat(CSTRING *cstring, const char *format, va_list ap);

EC_BOOL cstring_load(CSTRING *cstring, int fd, UINT32 *offset);

EC_BOOL cstring_flush(const CSTRING *cstring, int fd, UINT32 *offset);

//EC_BOOL cstring_regex(const CSTRING *cstring, const CSTRING *pattern, CVECTOR *cvector_cstring);

#endif/* _CSTRING_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
