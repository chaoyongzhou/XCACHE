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

#ifndef _CCONSOLE_H
#define _CCONSOLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "type.h"

#include "mm.h"

#include "cmisc.h"
#include "log.h"

EC_BOOL cconsole_catach_signals_disable();

EC_BOOL cconsole_catach_signals_enable();

EC_BOOL cconsole_cmd_get(const char *prompt, char *cmd, const uint32_t max_len, uint32_t *len);

EC_BOOL cconsole_cmd_add_history(const char *cmd);

const char *cconsole_cmd_get_history(const uint32_t hist_idx);

EC_BOOL cconsole_cmd_print_history(LOG *log);

EC_BOOL cconsole_cmd_clear_history();

#endif/*_CCONSOLE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


