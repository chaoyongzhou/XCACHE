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

#ifndef _API_CMD_H
#define _API_CMD_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "cstring.h"
#include "log.h"

#include "api_cmd.inc"


UINT8 *api_cmd_greedy_space(const UINT8 *pbeg, const UINT8 *pend);

UINT8 * api_cmd_greedy_uint32(const UINT8 *pbeg, const UINT8 *pend, UINT32 *value);

UINT8 * api_cmd_greedy_uint64(const UINT8 *pbeg, const UINT8 *pend, uint64_t *num);

UINT8 * api_cmd_greedy_real(const UINT8 *pbeg, const UINT8 *pend, REAL *value);

UINT8 * api_cmd_greedy_tcid(const UINT8 *pbeg, const UINT8 *pend, UINT32 *tcid);

UINT8 * api_cmd_greedy_mask(const UINT8 *pbeg, const UINT8 *pend, UINT32 *mask);

UINT8 * api_cmd_greedy_ipaddr(const UINT8 *pbeg, const UINT8 *pend, UINT32 *ipaddr);

UINT8 * api_cmd_greedy_cstring(const UINT8 *pbeg, const UINT8 *pend, CSTRING *cstring);

UINT8 *api_cmd_greedy_word(const UINT8 *pbeg, const UINT8 *pend, UINT8 *word, UINT32 max_len);

CMD_TREE *api_cmd_tree_new();

EC_BOOL api_cmd_tree_init(CMD_TREE *cmd_tree);

EC_BOOL api_cmd_tree_clean(CMD_TREE *cmd_tree);

EC_BOOL api_cmd_tree_free(CMD_TREE *cmd_tree);

CMD_SEG *api_cmd_tree_add(CMD_TREE *cmd_tree, const CMD_SEG *cmd_seg);

EC_BOOL api_cmd_tree_define(CMD_TREE *cmd_tree, CMD_HANDLER cmd_handler, const UINT8 *cmd_fmt, va_list ap);

EC_BOOL api_cmd_tree_parse(const CMD_TREE *cmd_tree, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec);

void api_cmd_tree_print(LOG *log, const CMD_TREE *cmd_tree, const UINT32 level);

CMD_SEG *api_cmd_seg_new();;

EC_BOOL api_cmd_seg_init(CMD_SEG *cmd_seg);

EC_BOOL api_cmd_seg_clean(CMD_SEG *cmd_seg);

EC_BOOL api_cmd_seg_free(CMD_SEG *cmd_seg);

EC_BOOL api_cmd_seg_cmp(const CMD_SEG *cmd_seg_1st, const CMD_SEG *cmd_seg_2nd);

void api_cmd_seg_print(LOG *log, const CMD_SEG *cmd_seg, const UINT32 level);

/*fetch word token*/
EC_BOOL api_cmd_seg_fetch(CMD_SEG *cmd_seg, const UINT8 *cmd_fmt, UINT8 **next_cmd_fmt, va_list ap);

EC_BOOL api_cmd_seg_parse(const CMD_SEG *cmd_seg, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec);

CMD_PARA *api_cmd_para_new();;

EC_BOOL api_cmd_para_init(CMD_PARA *cmd_para);

EC_BOOL api_cmd_para_clean(CMD_PARA *cmd_para);

EC_BOOL api_cmd_para_free(CMD_PARA *cmd_para);

EC_BOOL api_cmd_para_set_uint32(CMD_PARA *cmd_para, const UINT32 value);

EC_BOOL api_cmd_para_set_uint64(CMD_PARA *cmd_para, const uint64_t value);

EC_BOOL api_cmd_para_set_tcid(CMD_PARA *cmd_para, const UINT32 tcid);

EC_BOOL api_cmd_para_set_real(CMD_PARA *cmd_para, const REAL *value);

EC_BOOL api_cmd_para_set_cstring(CMD_PARA *cmd_para, CSTRING *cstring);

EC_BOOL api_cmd_para_get_uint32(const CMD_PARA *cmd_para, UINT32 *value);

EC_BOOL api_cmd_para_get_uint64(const CMD_PARA *cmd_para, uint64_t *value);

EC_BOOL api_cmd_para_get_tcid(const CMD_PARA *cmd_para, UINT32 *tcid);

EC_BOOL api_cmd_para_get_mask(const CMD_PARA *cmd_para, UINT32 *mask);

EC_BOOL api_cmd_para_get_ipaddr(const CMD_PARA *cmd_para, UINT32 *ipaddr);

EC_BOOL api_cmd_para_get_real(const CMD_PARA *cmd_para, REAL *value);

EC_BOOL api_cmd_para_get_cstring(const CMD_PARA *cmd_para, CSTRING **cstring);

void api_cmd_para_print(LOG *log, const CMD_PARA *cmd_para);

CMD_PARA_VEC *api_cmd_para_vec_new();;

EC_BOOL api_cmd_para_vec_init(CMD_PARA_VEC *cmd_para_vec);

EC_BOOL api_cmd_para_vec_clean(CMD_PARA_VEC *cmd_para_vec);

EC_BOOL api_cmd_para_vec_free(CMD_PARA_VEC *cmd_para_vec);

EC_BOOL api_cmd_para_vec_get_uint32(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *value);

EC_BOOL api_cmd_para_vec_get_uint64(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, uint64_t *value);

EC_BOOL api_cmd_para_vec_get_tcid(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *tcid);

EC_BOOL api_cmd_para_vec_get_mask(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *mask);

EC_BOOL api_cmd_para_vec_get_ipaddr(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *ipaddr);

EC_BOOL api_cmd_para_vec_get_real(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, REAL *value);

EC_BOOL api_cmd_para_vec_get_cstring(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, CSTRING **cstring);

EC_BOOL api_cmd_para_vec_add(CMD_PARA_VEC *cmd_para_vec, const CMD_PARA *cmd_para);

void api_cmd_para_vec_print(LOG *log, const CMD_PARA_VEC *cmd_para_vec);

CMD_HELP *api_cmd_help_new();

EC_BOOL api_cmd_help_init(CMD_HELP *cmd_help);

EC_BOOL api_cmd_help_clean(CMD_HELP *cmd_help);

EC_BOOL api_cmd_help_free(CMD_HELP *cmd_help);

EC_BOOL api_cmd_help_set(CMD_HELP *cmd_help, const char *cmd_help_abbr, const char *cmd_help_syntax);

EC_BOOL api_cmd_help_cmp(CMD_HELP *cmd_help_1st, CMD_HELP *cmd_help_2nd);

void api_cmd_help_print(LOG *log, const CMD_HELP *cmd_help);

CMD_HELP_VEC *api_cmd_help_vec_new();

EC_BOOL api_cmd_help_vec_init(CMD_HELP_VEC *cmd_help_vec);

EC_BOOL api_cmd_help_vec_clean(CMD_HELP_VEC *cmd_help_vec);

EC_BOOL api_cmd_help_vec_free(CMD_HELP_VEC *cmd_help_vec);

EC_BOOL api_cmd_help_vec_add(CMD_HELP_VEC *cmd_help_vec, const CMD_HELP *cmd_help);

EC_BOOL api_cmd_help_vec_create(CMD_HELP_VEC *cmd_help_vec, const char *cmd_help_abbr, const char *cmd_help_syntax);

void api_cmd_help_vec_print(LOG *log, const CMD_HELP_VEC *cmd_help_vec);

CMD_ELEM *api_cmd_elem_new();

EC_BOOL api_cmd_elem_init(CMD_ELEM *cmd_elem);

EC_BOOL api_cmd_elem_clean(CMD_ELEM *cmd_elem);

EC_BOOL api_cmd_elem_free(CMD_ELEM *cmd_elem);

CMD_ELEM *api_cmd_elem_create_uint32(const char *word);

CMD_ELEM *api_cmd_elem_create_uint64(const char *word);

CMD_ELEM *api_cmd_elem_create_cstring(const char *word);

CMD_ELEM *api_cmd_elem_create_tcid(const char *word);

CMD_ELEM *api_cmd_elem_create_mask(const char *word);

CMD_ELEM *api_cmd_elem_create_ipaddr(const char *word);

CMD_ELEM *api_cmd_elem_create_list(const char *word);

CMD_ELEM *api_cmd_elem_create_list_item(CMD_ELEM *cmd_elem_list, const char *word, const UINT32 value);

EC_BOOL api_cmd_elem_find_list_item(CMD_ELEM *cmd_elem_list, const char *word, UINT32 *value);

CMD_ELEM_VEC *api_cmd_elem_vec_new();

EC_BOOL api_cmd_elem_vec_init(CMD_ELEM_VEC *cmd_elem_vec);

EC_BOOL api_cmd_elem_vec_clean(CMD_ELEM_VEC *cmd_elem_vec);

EC_BOOL api_cmd_elem_vec_free(CMD_ELEM_VEC *cmd_elem_vec);

EC_BOOL api_cmd_elem_vec_add(CMD_ELEM_VEC *cmd_elem_vec, const CMD_ELEM *cmd_elem);

EC_BOOL api_cmd_comm_define(CMD_TREE *cmd_tree, CMD_HANDLER cmd_handler, const char *cmd_fmt, ...);

EC_BOOL api_cmd_comm_help(LOG *log, const CMD_HELP_VEC *cmd_tree);

EC_BOOL api_cmd_comm_parse(const CMD_TREE *cmd_tree, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec);

#endif/*_API_CMD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

