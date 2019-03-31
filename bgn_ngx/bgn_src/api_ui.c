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

#include "type.h"
#include "log.h"

#include "api_ui.inc"
#include "api_ui.h"
#include "api_ui_cp.h"
#include "api_ui_util.h"
#include "api_ui_printf.h"
#include "api_ui_malloc.h"

#include "api_ui_help.h"

#include "api_ui_log.h"

#include "cstring.h"

#include "log.h"
#include "mm.h"

/* Global variables */
static API_UI_NODE* api_ui_cmd_tree_g = NULL_PTR;
static char *api_ui_undefined_helpstr_g = (char *)"N/A";
static const char *api_ui_cmd_prompt = (char *)"bgn> ";

API_UI_NODE *api_ui_cmd_tree()
{
    return api_ui_cmd_tree_g;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_init
 *
 * Input        Description
 * -----        -----------
 * - none -
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *  This function is used to initialize UI globals.
 *
 *---------------------------------------------------------------------------*/
void api_ui_init()
{
    /* Initialize pointer to command tree */
    api_ui_cmd_tree_g = NULL_PTR;
}


/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_task
 *
 * Input        Description
 * -----        -----------
 * args         arguments to pthread
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This is the the _api_ui_task.  It will parse user input into the ui_argc and
 *     ui_agrv variables expected by api handler code.
 *
 *---------------------------------------------------------------------------*/
void api_ui_task ()
{

    char  ui_command[API_UI_TASK_COMMANDSIZE+1]; /* hold user input, extra char for termination */
    int   ui_argc;           /* number of space seperated stuff on user input */
    char *ui_argv[NUM_ARGV_ENTRIES];   /* pointers to the null terminated stuff */
    char *ptr;              /* temp pointer used to work on input string */
    char *pend;

    /* installing help command */
    api_ui_help_init();

    //setbuf(stdout, (char *)0); disable buffer mode of stdout, or fflush(stdout) when fputs, see below codes.

    /* Check for a message from the ubsUIShell */
    for(;;)
    {
        memset(ui_command,'\0',API_UI_TASK_COMMANDSIZE+1);

        //fputs("\ninput a command: ", LOGSTDOUT);
        fputs(api_ui_cmd_prompt, stdout);
        fflush(stdout);
        fgets(ui_command, API_UI_TASK_COMMANDSIZE, stdin);

        ui_command[API_UI_TASK_COMMANDSIZE] = 0;
        ui_command[strlen(ui_command) - 1] = '\0';
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "[%s]\n", ui_command);

        /* Replease newline character of the ui command
         * with null character so that we dont process
         * the empty command and also so that we remove the
         * newline for every command line
         */
        ptr = strchr(ui_command,'\n');
        if(ptr != NULL_PTR)
        {
            *ptr = '\0';
        }

        /* parse into argc and argv -
           this could be compressed at the cost of readability */

        ui_argc = 0;
        ptr = (char *)ui_command;
        pend = (char *)ui_command + strlen((char *)ui_command);

        while(ptr < pend)
        {
            ptr += strspn(ptr," '");

            ui_argv[ui_argc++] = ptr;

            if((ptr != (char *)ui_command && *(ptr - 1) == '\''))
            {
                ptr += strcspn(ptr,"'");
                *ptr++ = '\0';
            }
            else
            {
                ptr += strcspn(ptr," ");
                *ptr++ = '\0';
            }

            //ptr += strspn(ptr, " '");
        }

        if (ui_argc > 0)
        {
            api_ui_cp(ui_argc, ui_argv, EC_FALSE, 4092, (API_UI_PRINTF_HANDLER)app_printf);
        }
    }
    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:  api_ui_add_to_new_node_list
 *
 * Input    Description
 * -----    -----------
 * start_ptr
 *          Pointer to the pointer that is the start of the new node list
 * node_ptr
 *          Pointer to a pointer for a node.
 *
 * Output      Description
 * ------      -----------
 * - none -
 *
 * Description:
 *     Adds new node pointers to the list.
 *---------------------------------------------------------------------------*/
void api_ui_add_to_new_node_list(API_UI_CNODE** start_ptr, API_UI_NODE** node_ptr)
{

    /* Get to the end of the linked list */
    while ( (*start_ptr) != NULL_PTR)
    {
        start_ptr = &((*start_ptr)->next);
    }

    (*start_ptr) = (API_UI_CNODE*) api_ui_malloc(sizeof(API_UI_CNODE), LOC_API_0442);

    if ((*start_ptr) != NULL_PTR)
    {
         /* Initialize the node */
        (*start_ptr)->node_ptr = node_ptr;
        (*start_ptr)->next = NULL_PTR;
    }
    return;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_cleanup
 *
 * Input        Description
 * -----        -----------
 * state       EC_TRUE if api_ui_define() executed without an error, EC_FALSE
 *             otherwise.
 * list        Pointer to the linked list of new nodes that were created.
 * copy_cmd_str
 *             Pointer to the copy of the command string.
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR Error from api_ui_define()
 *
 * Description:
 *     This function performs some cleanup tasks before api_ui_define
 *     returns.  Here is a list of what is done:
 *         1. Copy of the command string is freed
 *         2. Mutex is released.
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_cleanup(API_UI_ERR err, char* copy_cmd_str, API_UI_CNODE* new_node_list)
{

    API_UI_CNODE* tmp_ptr;
    API_UI_NODE* node;

    tmp_ptr = new_node_list;

    /* Was there a problem in creating the command? */
    if (err != API_EUI_OK)
    {

        /* Remove all new nodes */
        while (tmp_ptr != NULL_PTR)
        {
            node = *(tmp_ptr->node_ptr);

            /* Remove all created API_UI_ELEM */
            if ( node->element->type == API_UI_ELEM_TYPE_SUBMENU )
            {
                api_ui_delete_elem(node->element);
            }

            *(tmp_ptr->node_ptr) = node->right;
            api_ui_free(node, LOC_API_0443);

            tmp_ptr = tmp_ptr->next;
        }
    }

    while(new_node_list != NULL_PTR)
    {
        tmp_ptr = new_node_list;
        new_node_list = tmp_ptr->next;
        api_ui_free(tmp_ptr, LOC_API_0444);
    }

    /* Free the copy of the command string */
    api_ui_free(copy_cmd_str, LOC_API_0445);

    return err;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_create_elem
 *
 * Input       Description
 * -----       -----------
 * word        Pointer to the word string to store in the new API_UI_ELEM
 * help        Pointer to the help string to store in the new API_UI_ELEM
 * type        The type of API_UI_ELEM
 *
 * Output      Description
 * ------      -----------
 * API_UI_ELEM*
 *             Pointer to a new API_UI_ELEM
 *
 * Description:
 *     This function allocates and initializes all new API_UI_ELEMs
 *---------------------------------------------------------------------------*/
API_UI_ELEM* api_ui_create_elem(const char* word, const char* help, API_UI_ELEM_TYPE type)
{
    API_UI_ELEM* returnValue = NULL_PTR;
    char* copy_word;
    int size;

    size = strlen(word) + 1; /* Don't forget '\0' */

    copy_word = (char*) api_ui_malloc(sizeof(char) * size, LOC_API_0446);

    if (NULL_PTR == copy_word)
    {
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_create_elem - Failed to allocate mamory");
        return returnValue;
    }

    strcpy(copy_word,word);

    returnValue = (API_UI_ELEM*) api_ui_malloc(sizeof(API_UI_ELEM), LOC_API_0447);

    if (NULL_PTR == returnValue)
    {
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_create_elem - Failed to allocate memory for returnValue");
        return returnValue;
    }

    returnValue->word = copy_word;

    returnValue->help = help;
    returnValue->type = type;
    returnValue->value = 0;
    returnValue->x.next = NULL_PTR;

    return returnValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_Create_Node
 *
 * Input        Description
 * -----        -----------
 * element     API_UI_ELEM associated with the new node
 * sl          API_UI_SECURITY_LEVEL security level of  node command execution
 *
 * Output       Description
 * ------       -----------
 * API_UI_NODE*
 *             Pointer to the new node that was created
 *
 * Description:
 *     This function creates a new node and initializes it.  The node is
 *     defined to be a subnode.
 *---------------------------------------------------------------------------*/
API_UI_NODE* api_ui_create_node(API_UI_ELEM* element, API_UI_SECURITY_LEVEL sl)
{
    API_UI_NODE* new_node;

    new_node = (API_UI_NODE*)api_ui_malloc(sizeof(API_UI_NODE), LOC_API_0448);

    if (new_node != NULL_PTR)
    {
        new_node->security_level = sl;
        new_node->type = API_UI_SUB_NODE;
        new_node->element = element;
        new_node->right = NULL_PTR;
        new_node->child.next = NULL_PTR;
    }

    return new_node;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_Delete_Elem
 *
 * Input        Description
 * -----        -----------
 * element     Element to be freed
 *
 * Output       Description
 * ------       -----------
 * - none -
 *
 * Description:
 *     This function goes about and performs all the necessary operation to
 *     free up an API_UI_ELEM element.
 *---------------------------------------------------------------------------*/
void api_ui_delete_elem(API_UI_ELEM* element)
{
    api_ui_free((void*)element->word, LOC_API_0449);
    api_ui_free(element, LOC_API_0450);
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_Get_Param
 *
 * Input        Description
 * -----        -----------
 * param_list  Pointer to the beginning of the parameter linked list
 * param_num   Specifies which parameter to "get".  The first parameter is
 *             specified when param_num is equal to 1.
 *
 * Output       Description
 * ------       -----------
 * API_UI_PARAM*
 *             Returns a pointer to the parameter that was to be fetched
 *
 * Description:
 *     This function is called by the interface functions that return the
 *     parameters to the UI handlers.
 *---------------------------------------------------------------------------*/
API_UI_PARAM* api_ui_Get_Param(API_UI_PARAM *param_list, int param_num)
{
     int i;

     for (i = 0; i < (param_num - 1); i++)
     {
          if (param_list == NULL_PTR)
          {
               return NULL_PTR;
          }

          param_list = param_list->next;
     }

     return param_list;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_insert_node_sl
 *
 * Input        Description
 * -----        -----------
 * node_ptr     Pointer to a pointer to a node where the insert is to occur
 * element      API_UI_ELEM associated with the new node
 *  sl          API_UI_SECURITY_LEVEL execution security level of inserted node
 *
 * Output       Description
 * ------       -----------
 * API_UI_NODE*
 *             Pointer to the new node that was created.
 *
 * Description:
 *     The function inserts a node into the command tree at the location
 *     specified.
 *---------------------------------------------------------------------------*/
API_UI_NODE* api_ui_insert_node_sl (API_UI_NODE** node_ptr, API_UI_ELEM* element, API_UI_SECURITY_LEVEL sl)
{
    API_UI_NODE* new_node;

    new_node = api_ui_create_node(element, sl);

    if(new_node != NULL_PTR)
    {
        new_node->right = (*node_ptr);
        (*node_ptr) = new_node;
    }

    return new_node;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_arg_float
 *
 * Input        Description
 * -----        -----------
 * arg_name    Name for the float argument
 * help_str    Help string for the float argument
 *
 * Output       Description
 * ------       -----------
 * API_UI_ELEM*
 *             Pointer to a float argument
 *
 * Description:
 *     Creates an argument that accepts a floating point number
 *---------------------------------------------------------------------------*/
API_UI_ELEM *api_ui_arg_float(char *arg_name, char *help_str)
{
    API_UI_ELEM* returnValue;

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    returnValue = api_ui_create_elem(arg_name, help_str, API_UI_ELEM_TYPE_FLOAT);

    return returnValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_arg_list
 *
 * Input        Description
 * -----        -----------
 * arg_name    Description of the list
 * help_str    Help string for the list
 *
 * Output       Description
 * ------       -----------
 * API_UI_ELEM*
 *             Pointer to an API_UI_ELEM data structure that is a list type
 *
 *
 * Description:
 *     This creates the head element for a list argument.
 *---------------------------------------------------------------------------*/
API_UI_ELEM* api_ui_arg_list(const char* arg_name, const char* help_str)
{
    API_UI_ELEM* returnValue;

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    returnValue = api_ui_create_elem(arg_name,help_str, API_UI_ELEM_TYPE_LIST);

    return returnValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_arg_list_item
 *
 * Input        Description
 * -----        -----------
 * list        List to add the item to
 * item_name   The name of the item to add to the list
 * value       The associated value of the item
 * help_str    The help string for the item
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR Returns API_UI_OK if the item was added to the list or
 *             API_UI_DUP_NAME/API_UI_DUP_VALUE if the name/value already
 *             exists in the list argument.
 *
 * Description:
 *     Lists contains a head element (CMD_LIST_TYPE) and is followed by
 *     items (CMD_LIST_ITEM_TYPE) in a linked list.
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_arg_list_item(API_UI_ELEM* list, const char* item_name,int value, const char* help_str)
{
    API_UI_ELEM* new_item;

    if (list->x.next != NULL_PTR)
    {
        do
        {
            list = list->x.next;

            if (strcmp(item_name,list->word) == 0)
            {
                return API_EUI_DUP_NAME;
            }

            if (list->value == value)
            {
                return API_EUI_DUP_VALUE;
            }

        } while(list->x.next != NULL_PTR);
    }

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    new_item = api_ui_create_elem(item_name,help_str, API_UI_ELEM_TYPE_LIST_ITEM);
    if(new_item == NULL_PTR)
    {
       dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_arg_list_item - api_ui_create_elem failed for item_name:%s", item_name);
       return API_EUI_PMEM_ALLOC_FAILED;
    }

    new_item->value = value;
    list->x.next = new_item;
    return API_EUI_OK;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_arg_range
 *
 * Input        Description
 * -----        -----------
 * arg_name    Name for the range argument
 * help_str    Help string associate with the range argument
 * low_value   Lower bound
 * high_value  Upper bound
 *
 * Output       Description
 * ------       -----------
 * API_UI_ELEM*
 *             Pointer to a range argument
 *
 *
 * Description:
 *     Creates a range argument with the specified bounds
 *---------------------------------------------------------------------------*/
API_UI_ELEM *api_ui_arg_range(const char *arg_name, const char *help_str,int low_value, int high_value)
{
    API_UI_ELEM* returnValue;

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    returnValue = api_ui_create_elem(arg_name, help_str, API_UI_ELEM_TYPE_RANGE);

    if(returnValue == NULL_PTR)
    {
       dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_arg_range - api_ui_create_elem failed for arg_name:%s",arg_name);
       return returnValue;
    }

    returnValue->value = low_value;
    returnValue->x.value = high_value;

    return returnValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_arg_num
 *
 * Input        Description
 * -----        -----------
 * arg_name    Name for the integer argument
 * help_str Help string for the integer argument
 *
 * Output       Description
 * ------       -----------
 * API_UI_ELEM*
 *             Pointer to an integer argument
 *
 * Description:
 *     Creates an argument that accepts any integer value
 *---------------------------------------------------------------------------*/
API_UI_ELEM *api_ui_arg_num(const char *arg_name, const char *help_str)
{
    API_UI_ELEM* returnValue;

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    returnValue = api_ui_create_elem(arg_name, help_str, API_UI_ELEM_TYPE_INTEGER);

    return returnValue;
}

API_UI_ELEM *api_ui_arg_tcid(const char *arg_name, const char *help_str)
{
    API_UI_ELEM* returnValue;

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    returnValue = api_ui_create_elem(arg_name, help_str, API_UI_ELEM_TYPE_TCID);

    return returnValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_arg_str
 *
 * Input        Description
 * -----        -----------
 * arg_name    Name for the string argument
 * help_str    Name for the integer argument
 *
 * Output       Description
 * ------       -----------
 * API_UI_ELEM*
 *             Pointer to a string argument
 *
 * Description:
 *     Creates an argument that accepts any string
 *---------------------------------------------------------------------------*/
API_UI_ELEM *api_ui_arg_str(const char *arg_name, const char *help_str)
{
    API_UI_ELEM* returnValue;

    if (help_str == NULL_PTR)
    {
        help_str = api_ui_undefined_helpstr_g;
    }
    returnValue = api_ui_create_elem(arg_name, help_str, API_UI_ELEM_TYPE_STR);

    return returnValue;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_define
 *
 * Input        Description
 * -----        -----------
 * handler     Pointer to a function that is to be executed if the user types
 *             the UI command specified by cmd_str.  If the pointer is
 *             NULL_PTR, then it is understood that the user is defining a help
 *             string rather than an UI command.
 *
 * help_str    This is the help string associated with the UI command
 *             specified by cmd_str
 *
 * cmd_str     This is the command string that is broken up into tokens.  A
 *             token can either be a word (which becomes a submenu), "%f"
 *             for a float argument, "%l" for a list argument, "%n" for an
 *             integer argument, "%r" for an integer range argument, or "%s"
 *             for a string argument.
 *
 * ...         Any extra arguments should be pointers to API_UI_ELEM data
 *             structures that correspond to the "%f", "%l", "%n", "%r", and
 *             "%s" tokens.
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR Returns one of the following errors...
 *
 * Description:
 *             This function installs a new UI command on the CTRL.
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_define(API_UI_HANDLER handler, char* help_str, char* cmd_str, ...)
{
    API_UI_ERR result;
    va_list params; /* Used to access extra arguments */

    /* Prepare to access extra arguments */
    va_start(params,cmd_str);

    result = api_ui_common_define (API_UI_SECURITY_USER, handler, help_str, cmd_str, params);
    va_end(params);

    return result;
}

/*------------------------------------------------------------------------------
 * Subroutine Name: api_ui_common_define
 *
 * Input       Description
 * -----       -----------
 * sl          acceptable security level for execution adding command
 *             (in api_ui_define() case is API_UI_SECURITY_USER)
 * handler     Pointer to a function that is to be executed if the user types
 *             the UI command specified by cmd_str.  If the pointer is
 *             NULL_PTR, then it is understood that the user is defining a help
 *             string rather than an UI command.
 *
 * help_str    This is the help string associated with the UI command
 *             specified by cmd_str
 *
 * cmd_str     This is the command string that is broken up into tokens.  A
 *             token can either be a word (which becomes a submenu), "%f"
 *             for a float argument, "%l" for a list argument, "%n" for an
 *             integer argument, "%r" for an integer range argument, or "%s"
 *             for a string argument.
 *
 * params      undetermined parameters list passed by api_ui_*define()
 *
 * Output          Description
 * ------          -----------
 * API_UI_ERR     Returns one of the following errors...
 *
 * Description:
 *             This function contains the common code for
 *             api_ui_define() and api_ui_secure_define().
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_common_define (API_UI_SECURITY_LEVEL sl, API_UI_HANDLER handler, const char* help_str, const char* cmd_str, va_list params)
{
    STRTOK_INSTANCE tokenizer; /* String token data structure */
    EC_BOOL command_exists = EC_TRUE; /* Assume the command exists */
    EC_BOOL allocation_failure = EC_FALSE;
    int node_exists;
    /* Used to determine whether or not to add a node to the command tree */
    int token_cmp; /* Used to compare token to submenu nodes */

    char *copy; /* Pointer to a copy of the cmd_str */
    char *token; /* Pointer to the individual tokens in the cmd_str copy */

    API_UI_NODE* prev_node = NULL_PTR; /* Used to keep track where we've been */
    API_UI_NODE* help_node = NULL_PTR; /* Determines assignment of help string*/
    int help_assign_esh = 0; /* Determine if help string added in ESH */

    API_UI_NODE** node = &(api_ui_cmd_tree_g);
        /* Current location in the command tree */
    API_UI_ELEM* elem_ptr; /* Element associated with the current token */
    API_UI_ELEM_TYPE type; /* Element type associated with current token */

    API_UI_CNODE* new_node_list = NULL_PTR;

    /* Copy the cmd_str */
    copy = (char*) api_ui_malloc(sizeof(char) * (strlen(cmd_str) + 1), LOC_API_0451);

    if (NULL_PTR == copy)
    {
        /* Free mutex */
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "Unable to allocate memory for UI command: %s", cmd_str);
        return API_EUI_PMEM_ALLOC_FAILED;
    }

    strcpy(copy,cmd_str);

    /* Initialize tokenizer */
    strtok_init(copy,(char *)" ",&tokenizer);
    token = next_token(&tokenizer);

    if (NULL_PTR == token)
    {
        /* Free mutex */
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "Invalid token for UI command: %s", cmd_str);
        return API_EUI_INVALID_TOKEN;
    }

    /* Start going through all the tokens */
    do
    {
        if (token[0] == '%')
        {
            /* We have a special token: %f, %l, %n, %r, %s */
            if ( (elem_ptr = va_arg(params,API_UI_ELEM*)) == NULL_PTR)
            {

                /* Can't find anymore extra parameters */
                va_end(params);
                return api_ui_cleanup(API_EUI_MISSING_ELEM,copy,new_node_list);
            }

            /* Determine which token was found */
            if (strcmp(token,"%f") == 0)
            {
                type = API_UI_ELEM_TYPE_FLOAT;
            }
            else if (strcmp(token,"%l") == 0)
            {
                type = API_UI_ELEM_TYPE_LIST;
            }
            else if (strcmp(token,"%n") == 0)
            {
                type = API_UI_ELEM_TYPE_INTEGER;
            }
            else if (strcmp(token,"%r") == 0)
            {
                type = API_UI_ELEM_TYPE_RANGE;
            }
            else if (strcmp(token,"%s") == 0)
            {
                type = API_UI_ELEM_TYPE_STR;
            }
            else if (strcmp(token,"%t") == 0)
            {
                type = API_UI_ELEM_TYPE_TCID;
            }
            else
            {
                /* Release the mutex */
                return api_ui_cleanup(API_EUI_INVALID_TOKEN,copy,new_node_list);
            }

            if (type != elem_ptr->type)
            {
                return api_ui_cleanup(API_EUI_INVALID_TYPE,copy,new_node_list);
            }
        }
        else
        {
            /* We're just have a normal word, so lets make it a SUBMENU */
            elem_ptr = NULL_PTR;
            type = API_UI_ELEM_TYPE_SUBMENU;
        }

        /* Assume that a node must be added to the command tree */
        node_exists = EC_FALSE;

        while ((node_exists == EC_FALSE) && (allocation_failure == EC_FALSE))
        {
            if ((*node) == NULL_PTR)
            {
                /* We reached the end of the command tree traversal */
                if (type == API_UI_ELEM_TYPE_SUBMENU)
                {
                    elem_ptr = api_ui_create_elem(token,api_ui_undefined_helpstr_g,
                            API_UI_ELEM_TYPE_SUBMENU);
                }
                node_exists = EC_TRUE;
                command_exists = EC_FALSE;

                /* Create a new node in the command tree */
                prev_node = api_ui_insert_node_sl(node,elem_ptr, sl);
                if (prev_node != NULL_PTR)
                {
                    api_ui_add_to_new_node_list(&new_node_list, node);

                    if (type == API_UI_ELEM_TYPE_SUBMENU)
                    {
                        help_assign_esh++;
                        help_node = prev_node;
                    }

                    node = &(prev_node->child.next);
                }
                else
                {
                    allocation_failure = EC_TRUE;
                }

            }
            else if ((*node)->element->type > type)
            {
                /* All sibling nodes are ordered according to their type */
                if (type == API_UI_ELEM_TYPE_SUBMENU)
                {
                    elem_ptr = api_ui_create_elem(token,api_ui_undefined_helpstr_g,
                            API_UI_ELEM_TYPE_SUBMENU);
                }

                node_exists = EC_TRUE;
                command_exists = EC_FALSE;
                prev_node = api_ui_insert_node_sl(node,elem_ptr, sl);
                if (prev_node != NULL_PTR)
                {
                    api_ui_add_to_new_node_list(&new_node_list, node);
                    if (type == API_UI_ELEM_TYPE_SUBMENU)
                    {
                        help_assign_esh++;
                        help_node = prev_node;
                    }
                    node = &(prev_node->child.next);
                }
                else
                {
                    allocation_failure = EC_TRUE;
                }
            }
            else if ( type == API_UI_ELEM_TYPE_SUBMENU &&
                    (token_cmp = strcmp(token,(*node)->element->word)) <= 0 )
            {
                /* Check to see if we have a SUBMENU match
                 *     Criteria: The SUBMENU words must match
                 */
                if (token_cmp == 0)
                {
                    node_exists = EC_TRUE;
                    prev_node = (*node);
                    node = &(prev_node->child.next);

                    if (prev_node->type == API_UI_LEAF)
                    {
                        return api_ui_cleanup(API_EUI_EXISTS,copy,new_node_list);
                    }
                }
                else
                { /* token_cmp < 0 */
                    elem_ptr = api_ui_create_elem(token,api_ui_undefined_helpstr_g,API_UI_ELEM_TYPE_SUBMENU);
                    node_exists = EC_TRUE;
                    command_exists = EC_FALSE;
                    prev_node = api_ui_insert_node_sl(node,elem_ptr, sl);
                    if (prev_node != NULL_PTR)
                    {
                        api_ui_add_to_new_node_list(&new_node_list, node);

                        help_assign_esh++;
                        help_node = prev_node;

                        node = &(prev_node->child.next);
                    }
                    else
                    {
                        allocation_failure = EC_TRUE;
                   }
                }
            }
            else if ( type != API_UI_ELEM_TYPE_SUBMENU &&
                        (*node)->element == elem_ptr)
            {
                /* Check to see if we have a non-SUBMENU match
                 *     Criteria: We must be refering to the same object, so
                 *       the pointers better be the same.
                 */
                node_exists = EC_TRUE;
                prev_node = (*node);
                node = &(prev_node->child.next);
            }
            else
            {
                /* Move on to the next sibling */
                prev_node = (*node);
                node = &(prev_node->right);
            }
            if (EC_TRUE == allocation_failure)
            {
                return api_ui_cleanup(API_EUI_PMEM_ALLOC_FAILED,copy,new_node_list);
            }
        }

    } while ( (token = next_token(&tokenizer)) != NULL_PTR);

    if (command_exists == EC_FALSE)
    {
        /* If the command didn't exist, see if we're defining an UI command or
         * help string
         */
        if (handler != NULL_PTR)
        {
            prev_node->child.handler = handler;
            prev_node->type = API_UI_LEAF;
        }
    }
    else
    {
        /* If the command does exist, make sure we're only trying to define a
        * help string and NOT a UI command.
        */
        if (handler != NULL_PTR)
        {
            return api_ui_cleanup(API_EUI_EXISTS,copy,new_node_list);
        }
    }

    /* Assign the help string */
    if (help_node != NULL_PTR)
    {
        help_node->element->help = help_str;
    }

    return api_ui_cleanup(API_EUI_OK,copy,new_node_list);
}

/*------------------------------------------------------------------------------
 * Subroutine Name: api_ui_secure_define
 *
 * Input        Description
 * -----        -----------
 * sl          acceptable security level for execution adding command
 *
 * handler     Pointer to a function that is to be executed if the user types
 *             the UI command specified by cmd_str.  If the pointer is
 *             NULL_PTR, then it is understood that the user is defining a help
 *             string rather than an UI command.
 *
 * help_str    This is the help string associated with the UI command
 *             specified by cmd_str
 *
 * cmd_str     This is the command string that is broken up into tokens.  A
 *             token can either be a word (which becomes a submenu), "%f"
 *             for a float argument, "%l" for a list argument, "%n" for an
 *             integer argument, "%r" for an integer range argument, or "%s"
 *             for a string argument.
 *
 * ...         Any extra arguments should be pointers to API_UI_ELEM data
 *             structures that correspond to the "%f", "%l", "%n", "%r", and
 *             "%s" tokens.
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR  Returns the status of defining the ui command.
 *
 * Description:
 *             This function installs a new UI command on the CTRL.
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_secure_define (API_UI_SECURITY_LEVEL sl, API_UI_HANDLER handler, const char* help_str, const char* cmd_str, ...)
{
    API_UI_ERR result = API_EUI_INVALID_PARAM;
    va_list params; /* Used to access extra arguments */

    /* Check if there is acceptable passed security level (sl parameter)*/
    if ((API_UI_SECURITY_USER != sl)
        && (API_UI_SECURITY_TESTER != sl)
        && (API_UI_SECURITY_ENGINEER  != sl))
    {
        dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_secure_define - Command has not been added to UI command tree "
                          "due to wrong security level");
        return result;
    }

    /* Prepare to access extra arguments */
    va_start(params,cmd_str);

    result = api_ui_common_define (sl, handler, help_str, cmd_str, params);
    va_end(params);

    return result;
};

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_param_float
 *
 * Input        Description
 * -----        -----------
 * Param       Start of the parameter linked list
 * arg_num     Parameter number to fetch (beginning at 1)
 * decimal_ptr Pointer to a floating pointer variable
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR Reports if any errors occurred while retrieving parameters
 *
 * Description:
 *     Returns the floating point number associated with the parameter
 *     specified
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_param_float(API_UI_PARAM *param_list, int param_num, float *decimal_ptr)
{
    if ( (param_list = api_ui_Get_Param(param_list,param_num)) == NULL_PTR)
    {
        return API_EUI_INVALID_PARAM;
    }

    if ( param_list->type != API_UI_PARAM_TYPE_FLOAT )
    {
        return API_EUI_INVALID_TYPE;
    }

    *decimal_ptr = param_list->x.decimal;
    return API_EUI_OK;
}

/*---------------------------------------------------------------------------
 * Subroutine Name:  api_ui_param_get_type
 *
 * Input    Description
 * -----    -----------
 * param_list  Start of the parameter linked list
 * param_num   Parameter number to fetch (beginning at 1)
 *
 * Output      Description
 * ------      -----------
 * API_UI_PARAM_TYPE
 *             The type of parameter #param_num.  If param_num is invalid,
 *             API_UI_PARAM_TYPE_NULL is returned.
 *
 * Description:
 *     Returns the floating point number associated with the parameter
 *     specified
 *---------------------------------------------------------------------------*/
API_UI_PARAM_TYPE api_ui_param_get_type(API_UI_PARAM *param_list, int param_num)
{
    if ((param_list = api_ui_Get_Param(param_list,param_num)) == NULL_PTR)
    {
        return API_UI_PARAM_TYPE_NULL;
    }
    return param_list->type;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_param_int
 *
 * Input        Description
 * -----        -----------
 * Param       Start of the parameter linked list
 * arg_num     Parameter number to fetch (beginning at 1)
 * value_ptr   Pointer to an integer variable
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR Reports if any errors occurred while retrieving parameters
 *
 * Description:
 *     Returns the integer of the parameter specified
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_param_int(API_UI_PARAM *param_list, int param_num, int *value_ptr)
{
    if ( (param_list = api_ui_Get_Param(param_list,param_num)) == NULL_PTR)
    {
        return API_EUI_INVALID_PARAM;
    }

    if ( param_list->type != API_UI_PARAM_TYPE_INTEGER )
    {
        return API_EUI_INVALID_TYPE;
    }

    *value_ptr = param_list->x.value;
    return API_EUI_OK;
}

/*---------------------------------------------------------------------------
 * Subroutine Name: api_ui_param_str
 *
 * Input        Description
 * -----        -----------
 * Param       Start of the parameter linked list
 * arg_num     Parameter number to fetch (beginning at 1)
 * str         Pointer to an array of characters where the string is to be
 *             copied
 * size        Number of characters in the string array
 *
 * Output       Description
 * ------       -----------
 * API_UI_ERR Reports if any errors occurred while retrieving parameters
 *
 * Description:
 *     Copies the string parameter to the character array that is passed as
 *     a parameter
 *---------------------------------------------------------------------------*/
API_UI_ERR api_ui_param_str(API_UI_PARAM *param_list, int param_num, char *str, size_t size)
{
    if ( (param_list = api_ui_Get_Param(param_list,param_num)) == NULL_PTR)
    {
        return API_EUI_INVALID_PARAM;
    }

    if ( param_list->type != API_UI_PARAM_TYPE_STR )
    {
        return API_EUI_INVALID_TYPE;
    }

    if (strlen(param_list->x.str) < size)
    {
        strcpy(str,param_list->x.str);
        return API_EUI_OK;
    }

    return API_EUI_STR_SIZE;
}

API_UI_ERR api_ui_param_cstring(API_UI_PARAM *param_list, int param_num, CSTRING *cstring)
{
    if ( (param_list = api_ui_Get_Param(param_list,param_num)) == NULL_PTR)
    {
        return API_EUI_INVALID_PARAM;
    }

    if ( param_list->type != API_UI_PARAM_TYPE_STR )
    {
        return API_EUI_INVALID_TYPE;
    }

    if(EC_FALSE == cstring_append_str(cstring, (UINT8 *)(param_list->x.str)))
    {
        return API_EUI_STR_SIZE;
    }

    return API_EUI_OK;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

