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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "type.h"

#include "mm.h"

#include "cmisc.h"
#include "log.h"

#include "cconsole.h"

EC_BOOL cconsole_catach_signals_disable()
{
    rl_catch_signals = 0;
    return (EC_TRUE);
}

EC_BOOL cconsole_catach_signals_enable()
{
    rl_catch_signals = 1;
    return (EC_TRUE);
}

EC_BOOL cconsole_cmd_get(const char *prompt, char *cmd, const uint32_t max_len, uint32_t *len)
{
    char        *command;
    uint32_t     length;

    command = readline(prompt);
    if(NULL_PTR == command)
    {
        dbg_log(SEC_0003_CCONSOLE, 0)(LOGSTDOUT, "error:cconsole_cmd_get: read nil cmd\n");
        return (EC_FALSE);
    }

    length = strlen(command);
    if(0 == length)
    {
        dbg_log(SEC_0003_CCONSOLE, 1)(LOGSTDOUT, "[DEBUG] cconsole_cmd_get: ignore empty cmd\n");
        free(command);

        return (EC_AGAIN);
    }

    if(length >= max_len)
    {
        dbg_log(SEC_0003_CCONSOLE, 0)(LOGSTDOUT, "error:cconsole_cmd_get: ignore overflow cmd '%s'\n", command);
        free(command);

        return (EC_AGAIN);
    }

    dbg_log(SEC_0003_CCONSOLE, 9)(LOGSTDOUT, "[DEBUG] cconsole_cmd_get: cmd '%s'\n", command);

    BCOPY(command, cmd, length + 1);
    (*len) = length;

    free(command);

    if(1 == (*len) && '!' == cmd[ 0 ])
    {
        dbg_log(SEC_0003_CCONSOLE, 1)(LOGSTDOUT, "error:cconsole_cmd_get: ignore invalid cmd '%s'\n", cmd);
        return (EC_AGAIN);/*ignore*/
    }

    if('!' == cmd[ 0 ])
    {
        uint32_t         hist_idx;

        /*check validity*/
        if(EC_FALSE == c_chars_are_digit(cmd + 1, (*len) - 1))
        {
            dbg_log(SEC_0003_CCONSOLE, 1)(LOGSTDOUT, "[DEBUG] cconsole_cmd_get: ignore invalid cmd '%s'\n", cmd);
            return (EC_AGAIN);/*ignore*/
        }

        hist_idx = c_chars_to_uint32_t(cmd + 1, (*len) - 1);

        command = (char *)cconsole_cmd_get_history(hist_idx);
        if(NULL_PTR == command)
        {
            dbg_log(SEC_0003_CCONSOLE, 1)(LOGSTDOUT, "[DEBUG] cconsole_cmd_get: get history cmd failed when ask for '%s'\n", cmd);
            return (EC_AGAIN);/*ignore*/
        }

        length  = strlen(command);

        if(length >= max_len)
        {
            dbg_log(SEC_0003_CCONSOLE, 0)(LOGSTDOUT, "error:cconsole_cmd_get: ignore overflow history cmd '%s'\n", command);
            return (EC_AGAIN);/*ignore*/
        }

        BCOPY(command, cmd, length + 1);
        (*len) = length;
    }

    return (EC_TRUE);
}

EC_BOOL cconsole_cmd_add_history(const char *cmd)
{
    add_history(cmd);
    return (EC_TRUE);
}

const char *cconsole_cmd_get_history(const uint32_t hist_idx)
{
    HIST_ENTRY      *hist_entry;

    if((int)hist_idx > history_length)
    {
        return (NULL_PTR);
    }

    hist_entry = history_get(hist_idx);
    if(NULL_PTR == hist_entry)
    {
        return (NULL_PTR);
    }

    return (const char *)hist_entry->line;
}

EC_BOOL cconsole_cmd_print_history(LOG *log)
{
    HIST_ENTRY      *hist_entry;
    int              idx;

    for(idx = history_base; NULL_PTR != (hist_entry = history_get(idx)); idx ++)
    {
        sys_print(log, "[%4d] %s\n", idx, hist_entry->line);
    }

    return (EC_TRUE);
}

EC_BOOL cconsole_cmd_clear_history()
{
    clear_history();
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

