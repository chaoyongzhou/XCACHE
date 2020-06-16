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
* Module Name   :   api_ui_cp.c
*
* Description:
*      This file contains the definition for the UI API Command Processor.
*      The Command Processor provides help to the user on the UI commands
*      which are available.
*
* Dependencies:
*
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <float.h>

#include "type.h"
#include "log.h"
#include "cmisc.h"

#include "api_ui.inc"
#include "api_ui.h"
#include "api_ui_cp.h"
#include "api_ui_util.h"
#include "api_ui_printf.h"
#include "api_ui_malloc.h"
#include "api_ui_log.h"

static char g_cmdstr[API_UI_TASK_COMMANDSIZE+1];

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_add_history
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 * element     An API_UI_ELEM that is to be added to the history linked list
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function adds an API_UI_ELEM to the history linked list.  The
 *     history linked list is kept to let the user know what was entered
 *     thus far during the interactive help.
 *---------------------------------------------------------------------------*/
void api_ui_cp_add_history(API_UI_INSTANCE* instance, API_UI_ELEM* element)
{
#if 0
    API_UI_HISTORY* new_node;
    API_UI_HISTORY** traverse;

    traverse = &(instance->history);

    new_node = (API_UI_HISTORY*) api_ui_malloc(sizeof(API_UI_HISTORY), LOC_API_0433);

    if (new_node != NULL)
    {
        new_node->element = element;
        new_node->next = NULL;

        /* Just add the new node to the end of the linked list */
        while (*traverse != NULL)
        {
            traverse = &((*traverse)->next);
        }

        *traverse = new_node;
    }
#endif
    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_add_param
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 * elment      Contains information about the type of parameter to store
 * word        Command line argument string
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function adds a parameter to the parameter linked list in instance.
 *     The API_UI_ELEM type determines whether the parameter will be a
 *     floating point number, integer, or a string.
 *---------------------------------------------------------------------------*/
void api_ui_cp_add_param(API_UI_INSTANCE* instance, API_UI_ELEM* element, char* word) {
    API_UI_PARAM* new_node;
    API_UI_PARAM** traverse;
    int string_length;

    traverse = &(instance->params);

    new_node = (API_UI_PARAM*) api_ui_malloc(sizeof(API_UI_PARAM), LOC_API_0434);

    if (new_node != NULL)
    {
        new_node->next = NULL;

        switch(element->type)
        {
            case API_UI_ELEM_TYPE_FLOAT:
                new_node->type = API_UI_PARAM_TYPE_FLOAT;

                new_node->x.decimal = atof(word);
                break;

            case API_UI_ELEM_TYPE_STR:
                new_node->type = API_UI_PARAM_TYPE_STR;

                string_length = strlen(word) + 1; /* Don't forget about '\0' */
                new_node->x.str = (char*)api_ui_malloc(sizeof(char)*string_length, LOC_API_0435);
                if (new_node->x.str != NULL)
                {
                    strcpy(new_node->x.str,word);
                }
                break;

            case API_UI_ELEM_TYPE_LIST_ITEM:
                new_node->type = API_UI_PARAM_TYPE_INTEGER;

                new_node->x.value = element->value;
                break;

            case API_UI_ELEM_TYPE_RANGE:
            case API_UI_ELEM_TYPE_INTEGER:
                new_node->type = API_UI_PARAM_TYPE_INTEGER;
                strtoint(word,&new_node->x.value);
                break;
            case API_UI_ELEM_TYPE_TCID:
                new_node->type = API_UI_PARAM_TYPE_INTEGER;
                new_node->x.value = (UINT32_TO_INT32(c_ipv4_to_word(word)));
                //dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "[DEBUG]word [%s] -> %ld\n", word, new_node->x.value);
                break;

            default:
                break;
        }

        while (*traverse != NULL)
            traverse = &((*traverse)->next);

        *traverse = new_node;
    }
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_Cleanup
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 *
 * Output       Description
 * ------       -----------
 * char*       Pointer to the output string that instance->output_string
 *             pointed to
 *
 * Description:
 *     This function goes about and frees up the all the linked lists in
 *     instance as well as instance itself.  The output string is not
 *     freed.
 *---------------------------------------------------------------------------*/
void api_ui_cp_cleanup(API_UI_INSTANCE* instance)
{
    API_UI_PARAM* tmp_params;
//    API_UI_HISTORY* tmp_history;

    /* Free up the parameter linked list */
    while(instance->params != NULL)
    {
        if (instance->params->type == API_UI_PARAM_TYPE_STR)
        {
            api_ui_free(instance->params->x.str, LOC_API_0436);
        }

        tmp_params = instance->params;
        instance->params = tmp_params->next;

        api_ui_free(tmp_params, LOC_API_0437);
    }
#if 0
    /* Free up the history linked list */
    while(instance->history)
    {
        tmp_history = instance->history;
        instance->history = tmp_history->next;

        api_ui_free(tmp_history, LOC_API_0438);
    }
#endif
    /* Free up the actual instance */
    api_ui_free(instance, LOC_API_0439);

    return;
}

/**
 * This functions executes UI handler
 *
 * Inputs/Outputs
 * @param instance Contains information about the processing of an UI command
 *
 * This function goes about and calls the UI handler.  The linked list
 * of parameters is passed to the handler and a char* is excepted
 * to be returned.  The char* should contain the output of the UI
 * command.
 */
void api_ui_cp_execute(API_UI_INSTANCE* instance)
{
    (*instance->current->child.handler)(instance->params);

    /* Set the command status */
    instance->state = CMD_PROC_EXEC_STATE;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_handle_word
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 * word        A command line argument
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function looks at each command line argument and traverses the
 *     command tree.
 *
 *---------------------------------------------------------------------------*/
void api_ui_cp_handle_word(API_UI_INSTANCE* instance, char* word)
{
    API_UI_NODE** cur_node_ptr = &(instance->current);
    API_UI_ELEM* cur_elem;

    /* The idea here is that depending on what node we are at
     * in the command tree, we shall try to see if word is a "match"
     */
    while ((*cur_node_ptr) != NULL)
    {

        cur_elem = (*cur_node_ptr)->element;

        switch(cur_elem->type)
        {

            case (API_UI_ELEM_TYPE_SUBMENU):
                if (EC_TRUE == api_ui_cp_submenu(instance,word))
                {
                    return;
                }
                break;
            case (API_UI_ELEM_TYPE_FLOAT):
            case (API_UI_ELEM_TYPE_STR):
            case (API_UI_ELEM_TYPE_INTEGER):
            case (API_UI_ELEM_TYPE_TCID):
            case (API_UI_ELEM_TYPE_LIST):
            case (API_UI_ELEM_TYPE_RANGE):
                if (EC_TRUE == api_ui_cp_param(instance,word))
                {
                    return;
                }
                break;
            default:
                break;
        }
    }

    api_ui_printf("warn: invalid command %s\n", word);

    /* Change the state to CMD_PROC_EXEC_STATE to drop out of the whole thing */
    instance->state = CMD_PROC_EXEC_STATE;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_help
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function displays the interactive help when the user enters
 *     an incomplete UI command.
 *---------------------------------------------------------------------------*/
void api_ui_cp_help(API_UI_INSTANCE* instance)
{
#if 0
    API_UI_HISTORY* history = instance->history;
#endif
    API_UI_NODE* cur_level = instance->current;
    API_UI_NODE* tmp_level;

    EC_BOOL single_command;

    /* Allocate output_string for the help message */
    single_command = EC_TRUE;
    tmp_level = cur_level;

    /* GCP would print out COMMAND PROCESSOR: HELP when it was in interactive
     * mode at the every beginning
      */

    /* Displaying the command history.  GCP did the same thing, and also
     * the idea of a PARTIAL SYNTAX and COMMAND SYNTAX are kept
     */
     while( (tmp_level != NULL) && (single_command != EC_FALSE) )
     {
          if (tmp_level->right != NULL)
          {
               single_command = EC_FALSE;
          }

          if (tmp_level->type == API_UI_LEAF)
          {
               tmp_level = NULL;
          }
          else
          {
               tmp_level = tmp_level->child.next;
          }
     }

    /* If there is only one valid command path, display COMMAND SYNTAX
     * If there are multi-paths (commands) display PARTIAL SYNTAX
     */
    if (EC_TRUE == single_command)
    {
        api_ui_printf("\nCOMMAND SYNTAX: ");
    }
    else
    {
        api_ui_printf("\nPARTIAL SYNTAX: ");
    }
#if 0
    /* Display the command syntax */
    while (history != NULL)
    {
        api_ui_printf("%s ",history->element->word);
        history = history->next;
    }
#endif
    /* Display the rest of the command if there is only one path */
    if (EC_TRUE == single_command)
    {
        tmp_level = cur_level;

        while(tmp_level != NULL)
        {
            api_ui_printf("%s ",tmp_level->element->word);

            if (tmp_level->type == API_UI_LEAF)
            {
                tmp_level = NULL;
            }
            else
            {
                tmp_level = tmp_level->child.next;
            }
        }
    }

    api_ui_printf("\n");

#if 0
    /* GCP would display the help string for each command argument that
       has already been entered.  This is a waste.
     */

    /* Display options */
    api_ui_printf("next available options:\n");
    while(cur_level != NULL)
    {
        API_UI_ELEM* tmp_elem;
        tmp_elem = cur_level->element;

        switch(tmp_elem->type)
        {
            case API_UI_ELEM_TYPE_SUBMENU:
                api_ui_printf("SUBMENU - %10s : %s\n",
                               tmp_elem->word, tmp_elem->help);
                break;
            case API_UI_ELEM_TYPE_LIST:
                api_ui_printf("   LIST - %10s : %s\n",
                               tmp_elem->word, tmp_elem->help);

                while(tmp_elem->x.next != NULL)
                {
                    tmp_elem = tmp_elem->x.next;
                    api_ui_printf("       %17s : %s\n",
                                     tmp_elem->word, tmp_elem->help);
                }
                break;
            case API_UI_ELEM_TYPE_FLOAT:
                api_ui_printf("  FLOAT - %10s : %s\n",
                                 tmp_elem->word, tmp_elem->help);
                break;
            case API_UI_ELEM_TYPE_RANGE:
                api_ui_printf("  RANGE - %10s : %s %2d - %2d\n",
                               tmp_elem->word,tmp_elem->help,
                               tmp_elem->value, tmp_elem->x.value);
                break;
            case API_UI_ELEM_TYPE_INTEGER:
                api_ui_printf("INTEGER - %10s : %s\n",
                                 tmp_elem->word,tmp_elem->help);
                break;
            case API_UI_ELEM_TYPE_STR:
                api_ui_printf(" STRING - %10s : %s\n",
                                 tmp_elem->word,tmp_elem->help);
                break;
            default:
                api_ui_printf("   %20s : %s\n",tmp_elem->word, tmp_elem->help);
        }

        cur_level = cur_level->right;
    }
#endif
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_Init
 *
 * Input        Description
 * -----        -----------
 * interactive Either enables(true) or disables(false) interactive help
 *
 * Output       Description
 * ------       -----------
 * API_UI_INSTANCE*
 *             A pointer to a structure that contains information about
 *             the processing/execution of an UI command.
 *
 * Description:
 *     This function creates an API_UI_INSTANCE data structure and initializes
 *     its state.
 *---------------------------------------------------------------------------*/
API_UI_INSTANCE* api_ui_cp_init(EC_BOOL interactive)
{
    API_UI_INSTANCE* retValue;

    retValue = (API_UI_INSTANCE*) api_ui_malloc(sizeof(API_UI_INSTANCE), LOC_API_0440);

    if (retValue != NULL)
    {
        retValue->interactive = interactive;

        /* Change CMD_PROC... to begin with API_UI... */
        retValue->state = CMD_PROC_INIT_STATE;
        retValue->params = NULL;
#if 0
        retValue->history = NULL;
#endif
        /* Change name of global root node to begin with api_ui... */
        retValue->current = api_ui_cmd_tree();
    }

    return retValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_Interactive
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function provides interactive help to the user when an incomplete
 *     UI command has been entered.  The user is prompted to enter the
 *     next argument for the UI command.  If the user enters nothing, the
 *     command is canceled.  If the user enters '?', the help message is
 *     displayed and the user is prompted to again enter the next argument.
 *---------------------------------------------------------------------------*/
void api_ui_cp_interactive(API_UI_INSTANCE* instance)
{
    STRTOK_INSTANCE tokenizer;
    char buffer[API_UI_TASK_COMMANDSIZE];
    char *token;
    char *ptr = NULL;

    /* Keep prompting until the command has been executed or
     * we each the end of the command tree path.
     */
    while(instance->state != CMD_PROC_EXEC_STATE &&
          instance->current != NULL)
    {
        api_ui_cp_help(instance);

        /* Just a very simple prompt */
        api_ui_printf("> ");

        /* Flush the api_ui_print buffer */
        api_ui_flush();

        /* Get the users input, if NULL is returned, fgets cannot read from LOGSTDIN,
         * in such case just return, error will be logged in api_ui_task*/
        ptr = fgets(buffer, API_UI_TASK_COMMANDSIZE, stdin);
        if(ptr == NULL)
        {

            return;
        }
        ptr = strchr(buffer,'\n');
        if(ptr != NULL)
        {
            *ptr = '\0';
        }

        /* storing command part in g_cmdstr variable */
        if (strlen(buffer) + strlen(g_cmdstr) < API_UI_TASK_COMMANDSIZE)
        {
            strcat(g_cmdstr, buffer);
            strcat(g_cmdstr, " ");
        }

        /* Check for blank entry and quit */
        /* Check for ? and display Help
            maybe the ? should be handled in api_ui_cp_handle_word */
        if (strlen(buffer) == 0)
        {
            api_ui_printf("CP: Command canceled\n");
            return;
        }

        /* If a '?' is entered, just jump back to the start of the
         * while loop
         */
        if (buffer[0] == '?')
            continue;

        strtok_init(buffer,(char *)" ",&tokenizer);
        for (token = next_token(&tokenizer);
            token != NULL && instance->state != CMD_PROC_EXEC_STATE;
            token = next_token(&tokenizer))
        {
            api_ui_cp_handle_word(instance,token);
        }
    }
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_next_level
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function updates the current element in instance to pointer to the
 *     next level in the comand tree.  If the next level is a function
 *     handler, then instance is marked as being an executed command.
 *---------------------------------------------------------------------------*/
void api_ui_cp_next_level(API_UI_INSTANCE* instance)
{
    API_UI_NODE* cur_node = instance->current;

    switch(cur_node->type)
    {
        case API_UI_SUB_NODE:
            instance->current = cur_node->child.next;
            return;
        /*  break;*/
        case API_UI_LEAF:
            api_ui_cp_execute(instance);
            return;
        /*  break;*/
        default:
            api_ui_printf("ERROR: Cannot traverse level.\n");
    }
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_Param
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 * word        The command line argument string pointer
 *
 * Output       Description
 * ------       -----------
 * EC_BOOL     Returns EC_TRUE if there is a match to word and to the current
 *             parameter (LIST,RANGE,STRING,INTEGER,FLOATE) element
 *             (API_UI_ELEM)
 *
 * Description:
 *     The command compares the string to the current API_UI_ELEM which is
 *     either a list, range, integer, string, or float.  If a match exists,
 *     EC_TRUE is returned, otherwise EC_FALSE is returned
 *---------------------------------------------------------------------------*/
EC_BOOL api_ui_cp_param(API_UI_INSTANCE* instance, char* word)
{
    API_UI_NODE* cur_node = instance->current;
    API_UI_ELEM* cur_elem = cur_node->element;
    int value;

    switch (cur_elem->type)
    {
        case (API_UI_ELEM_TYPE_FLOAT):
            if (EC_TRUE == api_ui_cp_valid_float(word))
            {
                api_ui_cp_add_history(instance,cur_elem);
                api_ui_cp_add_param(instance,cur_elem,word);
                api_ui_cp_next_level(instance);
                return EC_TRUE;
            }
            break;

        case (API_UI_ELEM_TYPE_LIST):

        /* If we are comparing word to a LIST, compare each item in the
         * list to see if there is a match
         */
            while(cur_elem->x.next != NULL)
            {
                cur_elem = cur_elem->x.next;

                if (strcmp(cur_elem->word,word) == 0)
                {
                    api_ui_cp_add_history(instance,cur_elem);
                    api_ui_cp_add_param(instance,cur_elem,word);
                    api_ui_cp_next_level(instance);
                    return EC_TRUE;
                }
            }
            break;

        case (API_UI_ELEM_TYPE_RANGE):
            if (api_ui_cp_valid_integer(word) != EC_FALSE)
            {
                strtoint(word,&value);
                if ( (value >= cur_elem->value) &&
                   (value <= cur_elem->x.value) )
                {
                    api_ui_cp_add_history(instance,cur_elem);
                    api_ui_cp_add_param(instance,cur_elem,word);
                    api_ui_cp_next_level(instance);
                    return EC_TRUE;
                }
            }
            break;
        case (API_UI_ELEM_TYPE_INTEGER):
            if (api_ui_cp_valid_integer(word) != EC_FALSE)
            {
                api_ui_cp_add_history(instance,cur_elem);
                api_ui_cp_add_param(instance,cur_elem,word);
                api_ui_cp_next_level(instance);
                return EC_TRUE;
            }
            break;
        case (API_UI_ELEM_TYPE_STR):
            if (strlen(word) != 0)
            {
                api_ui_cp_add_history(instance,cur_elem);
                api_ui_cp_add_param(instance,cur_elem,word);
                api_ui_cp_next_level(instance);
                return EC_TRUE;
            }
            break;
        case (API_UI_ELEM_TYPE_TCID):
            if (strlen(word) != 0)
            {
                api_ui_cp_add_history(instance,cur_elem);
                api_ui_cp_add_param(instance,cur_elem,word);
                api_ui_cp_next_level(instance);
                return EC_TRUE;
            }
            break;
        default:
            break;
    }
    instance->current = cur_node->right;
    return EC_FALSE;
}


/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_submenu
 *
 * Input        Description
 * -----        -----------
 * instance    Contains information about the processing of an UI command
 * word        The command line argument string pointer
 *
 * Output       Description
 * ------       -----------
 * EC_BOOL     Returns EC_TRUE if there is a match to word and to the current
 *             submenu element (API_UI_ELEM)
 *
 * Description:
 *---------------------------------------------------------------------------*/
EC_BOOL api_ui_cp_submenu(API_UI_INSTANCE* instance, char* word)
{
    API_UI_NODE* cur_node = instance->current;
    API_UI_ELEM* cur_elem = cur_node->element;

    if (strcmp(cur_elem->word,word) == 0)
    {
        api_ui_cp_add_history(instance,cur_elem);
        api_ui_cp_next_level(instance);
        return EC_TRUE;
    }

    instance->current = cur_node->right;
    return EC_FALSE;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_valid_float
 *
 * Input        Description
 * -----        -----------
 * word     The command line argument
 *
 * Output       Description
 * ------       -----------
 * EC_BOOL     Returns true if a valid float is in the string
 *
 * Description: 	This function validates that a string can properly be
 *                  into a floating point decimal.
 *---------------------------------------------------------------------------*/
EC_BOOL api_ui_cp_valid_float(char* word)
{
    double value;
    char* endptr;

    value = strtod(word,&endptr);

    if (*endptr == '\0')
    {
        if (value >= -(FLT_MAX) && value <= FLT_MAX)
        {
            return EC_TRUE;
        }
    }

    return EC_FALSE;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp_valid_integer
 *
 * Input        Description
 * -----        -----------
 * word        The command line argument
 *
 * Output       Description
 * ------       -----------
 * EC_BOOL     Returns true if a valid integer is in the string
 *
 * Description:
 *     This function validates if an integer exists in a string.
 *---------------------------------------------------------------------------*/
EC_BOOL api_ui_cp_valid_integer(char* word)
{
    int value;

    if (strtoint(word,&value) != EC_FALSE)
    {
        if (value >= INT_MIN && value <= INT_MAX)
        {
            return EC_TRUE;
        }
    }

    return EC_FALSE;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cp
 *
 * Input        Description
 * -----        -----------
 * argc        Number of command line arguments
 * argv        Pointers to command line argument strings
 * interactive A boolean which determines if the command processing is
 *             interactive
 *
 * buffer_sz      the buffer size of printing function
 * print_handler  handling function for api_ui_printf()
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Return value:
 * -------------
 *  - none -
 *
 * Description:
 *     This function processes the command line arguments, provides
 *     interactive help, and executes the appropiate UI handler.
 *---------------------------------------------------------------------------*/
void api_ui_cp(int argc, char** argv, EC_BOOL interactive, size_t buffer_sz, API_UI_PRINTF_HANDLER print_handler)
{
    API_UI_INSTANCE* instance;
    int i;

    g_cmdstr[0] = '\0'; /* init the current command string */
    /*
    There is a problem with functions that have multiple
    parameters... look at UNIX man page for "varargs"
    */
    api_ui_register(buffer_sz,print_handler);
    instance = api_ui_cp_init(interactive);

    if(NULL == instance)
    {
        api_ui_unregister();
        return;
    }

    /* storing current command in g_cmdstr variable */
    for (i = 0; i < argc ; i++)
    {
        if (strlen(argv[i]) + strlen(g_cmdstr) < API_UI_TASK_COMMANDSIZE)
        {
            strcat(g_cmdstr, argv[i]);
            strcat(g_cmdstr, " ");
        }
    }

    /* Start chewing the words up */
    for (i = 0; i < argc && instance->state != CMD_PROC_EXEC_STATE ; i++)
    {
        api_ui_cp_handle_word(instance, argv[i]);
    }
#if 0
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "instance state %d, interactive %d <--> CMD_PROC_EXEC_STATE(%d), EC_FALSE(%d)\n",
                    instance->state, instance->interactive,
                    CMD_PROC_EXEC_STATE, EC_FALSE);
#endif
#if 1
    /* Check to see if the command has already executed */
    if (instance->state != CMD_PROC_EXEC_STATE)
    {
        if (instance->interactive != EC_FALSE)
        {
            api_ui_cp_interactive(instance);
        }
        else
        {
            api_ui_cp_help(instance);
        }
    }
#endif
    //dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "before api_ui_unregister");
    api_ui_unregister();

    //dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "before api_ui_cp_Cleanup");
    api_ui_cp_cleanup(instance);
    instance = NULL;

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


