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


/***************************************************************************
* Module Name   :   api_ui_util.c
*
* Description:
*     This file contains functions that parses strings into command line
*     arguments.
*
* Dependencies:
*
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "type.h"
#include "api_ui.inc"
#include "api_ui.h"
#include "api_ui_util.h"
#include "api_ui_malloc.h"
#include "api_ui_log.h"
/*---------------------------------------------------------------------------
 * Subroutine Name:    api_ui_parse_cmdline()
 *
 * Input        Description
 * -----        -----------
 * cmdline  String containing the command line to be parsed.
 *          NOTE: This string will be modified!
 *
 * argc_ptr Pointer to an integer that will contain the number of arguments
 *          in the string 'cmdline'
 *
 * argv_ptr Pointer to an array the contains all the arguments in the string
 *          'cmdline'.
 *          NOTE: The memory allocated to create this array must be freed
 *          by the calling function.
 *
 * Output        Description
 * ------        -----------
 * - none -
 *
 * Description:
 *     This function will parse a command string into its arguments.
 *---------------------------------------------------------------------------*/
void api_ui_parse_cmdline(char* cmdline, int* argc_ptr, char*** argv_ptr) {
    char* cpy_cmdline;
    int i;
    STRTOK_INSTANCE token_instance;

    /* 'i' equals the length of the 'cmdline' string (including '\0') */
    i = strlen(cmdline);
    i++;

    cpy_cmdline = (char*)api_ui_malloc(sizeof(char) * i, LOC_API_0469);
    if(cpy_cmdline != NULL)
    {
        strcpy(cpy_cmdline, cmdline);
    }

    (*argc_ptr) = 0;

    /* Find out how many arguments are in the command line */
    strtok_init(cpy_cmdline,(char *)" ",&token_instance);
    while (next_token(&token_instance) != NULL)
        (*argc_ptr)++;
    api_ui_free(cpy_cmdline, LOC_API_0470);

    (*argv_ptr) = (char**)api_ui_malloc(sizeof(char*) * (*argc_ptr), LOC_API_0471);

    if ( (*argv_ptr) != NULL)
    {
          /* Build the argv array */
        strtok_init(cmdline,(char *)" ",&token_instance);
        for (i = 0; i < (*argc_ptr); i++)
            (*argv_ptr)[i] = next_token(&token_instance);
    }

    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:    next_token()
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output        Description
 * ------        -----------
 * - none -
 *  -or-
 * - returns -
 *
 *
 * Description:
 *---------------------------------------------------------------------------*/
char* next_token(STRTOK_INSTANCE* instance) {
    char* ret;
    int n;

    n = strspn(instance->string,instance->token);

    ret = instance->string + n;

    if (*ret == '\0')
        return NULL;

    instance->string = ret;

    /* Check for a quote */
    if ( *(instance->string) == '"') {
        /* Skip over the first quotation mark */
        ret++;

        /* Don't forget to shift the 'instance->string' over by one or else
         * we'll be out of sync
         */
        instance->string++;

        /* Find the next quotation mark */
        n = strcspn(ret,"\"");
    } else
        n = strcspn(instance->string,instance->token);

    instance->string += n;

    if(*(instance->string) != '\0') {
        *(instance->string) = '\0';
        instance->string++;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output        Description
 * ------        -----------
 * - none -
 *  -or-
 * - returns -
 *
 *
 * Description:
 *---------------------------------------------------------------------------*/
void strtok_init(char* string, char* token, STRTOK_INSTANCE* instance) {
    instance->string = string;
    instance->token = token;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output        Description
 * ------        -----------
 * - none -
 *  -or-
 * - returns -
 *
 *
 * Description:
 *---------------------------------------------------------------------------*/
EC_BOOL strtoint(char* string, int* value) {
    int str_length;
    int base;
    int i;
    int numerial;
    EC_BOOL negative = EC_FALSE;

    /* Check if the number is negitive */
    if (string[0] == '-') {
        negative = EC_TRUE;
        string++;
    }

    str_length = strlen(string);

    if (string == strstr(string,"0x")) {
        base = 16;
        string += 2;
    } else if (string[0] == '0')
        base = 8;
    else
        base = 10;

    (*value) = 0;

    str_length = strlen(string);

    for (i = 0; i < str_length; i++) {
        if (string[i] > 47 && string[i] < 56 && base == 8)
            numerial = string[i] - 48;
        else if (string[i] > 47 && string[i] < 58 && (base == 10 || base == 16))
            numerial = string[i] - 48;
        else if (string[i] > 64 && string[i] < 71 && base == 16)
            numerial = string[i] - 55;
        else if (string[i] > 96 && string[i] < 103 && base == 16)
            numerial = string[i] - 87;
        else
            return EC_FALSE;

        (*value) = (*value) * base + numerial;
    }

    if (negative != EC_FALSE)
        (*value) = -(*value);

    return EC_TRUE;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output        Description
 * ------        -----------
 * - none -
 *  -or-
 * - returns -
 *
 *
 * Description:
 *---------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

