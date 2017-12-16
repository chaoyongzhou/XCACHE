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

#ifndef _API_UI_INC
#define _API_UI_INC

#include <stddef.h>
#include <stdarg.h>

#include "type.h"


typedef struct
{
    char*    string;
    char*    token;
    char*    next;
} STRTOK_INSTANCE;

typedef int (*FUNCPTR) ();

typedef struct commandType
{
    char          *name;
    int            flags;
    FUNCPTR        handler;
    const char    *help;
}command;


/*---------------------------------------------------------------------------
 * Enumerated type name: api_ui_elem_type
 *
 * Set of all UI element types
 *---------------------------------------------------------------------------*/

#define       API_UI_ELEM_TYPE_NULL                  ((UINT32) 0)
#define       API_UI_ELEM_TYPE_SUBMENU               ((UINT32) 1)
#define       API_UI_ELEM_TYPE_LIST                  ((UINT32) 2)
#define       API_UI_ELEM_TYPE_LIST_ITEM             ((UINT32) 3)
#define       API_UI_ELEM_TYPE_RANGE                 ((UINT32) 4)
#define       API_UI_ELEM_TYPE_INTEGER               ((UINT32) 5)
#define       API_UI_ELEM_TYPE_FLOAT                 ((UINT32) 6)
#define       API_UI_ELEM_TYPE_STR                   ((UINT32) 7)
#define       API_UI_ELEM_TYPE_TCID                  ((UINT32) 8)

typedef UINT32 API_UI_ELEM_TYPE;


/*---------------------------------------------------------------------------
 * Structure name: struct api_ui_elem
 *
 * UI element structure
 *
 * word      : Word associated with UI element
 * help      : Help string for UI element
 * type      : Element type
 * value     : Element value (lower bound for range elements)
 * x.next    : Pointer to sibling element
 * x.value   : Higher bound for range elements
 *---------------------------------------------------------------------------*/

typedef struct api_ui_elem
{
    const char        *word;
    const char        *help;
    API_UI_ELEM_TYPE   type;
    int                value;

    union
    {
        struct api_ui_elem* next;
        int value;
    } x;

} API_UI_ELEM;

/*---------------------------------------------------------------------------
 * Define API_UI_TASK_NAME
 *
 * name of the api_ui_task
 *---------------------------------------------------------------------------*/

#define API_UI_TASK_COMMANDSIZE 1024    /* maximum size of an ui command */
#define NUM_ARGV_ENTRIES 100

/*---------------------------------------------------------------------------
 * Enumerated type name: api_ui_err
 *
 * Set of UI errors
 *---------------------------------------------------------------------------*/
#define        API_EUI_OK                      ((UINT32) 0)
#define        API_EUI_EXISTS                  ((UINT32) 1)
#define        API_EUI_MISSING_ELEM            ((UINT32) 2)
#define        API_EUI_INVALID_TYPE            ((UINT32) 3)
#define        API_EUI_INVALID_TOKEN           ((UINT32) 4)
#define        API_EUI_INVALID_CMD             ((UINT32) 5)
#define        API_EUI_DUP_NAME                ((UINT32) 6)
#define        API_EUI_DUP_VALUE               ((UINT32) 7)
#define        API_EUI_STR_SIZE                ((UINT32) 8)
#define        API_EUI_INVALID_PARAM           ((UINT32) 9)
#define        API_EUI_PMEM_ALLOC_FAILED       ((UINT32)10)

typedef UINT32 API_UI_ERR;


/*---------------------------------------------------------------------------
* Enumeration name: enum api_ui_param_type
 *
 * List of possible types for parameters
 *---------------------------------------------------------------------------*/
#define        API_UI_PARAM_TYPE_NULL               ((UINT32) 0)
#define        API_UI_PARAM_TYPE_INTEGER            ((UINT32) 1)
#define        API_UI_PARAM_TYPE_FLOAT              ((UINT32) 2)
#define        API_UI_PARAM_TYPE_STR                ((UINT32) 3)

typedef UINT32 API_UI_PARAM_TYPE;


/* -----------------------------------------------------------------------------
    Enumeration for the UI command security levels. User is the
    lowest security level. Engineer is the highest security level.
*/
#define     API_UI_SECURITY_USER              ((UINT32) 0)
#define     API_UI_SECURITY_TESTER            ((UINT32) 1)
#define     API_UI_SECURITY_ENGINEER          ((UINT32) 2)
#define     API_UI_SECURITY_MAX_ITEM          ((UINT32) 3)

typedef UINT32 API_UI_SECURITY_LEVEL;


/*---------------------------------------------------------------------------
 * Structure name: struct api_ui_param
 *
 * Linked list of parameters passed into UI handlers
 *
 * type      : Contains what type of information the parameter holds
 * x.value   : Integer parameter
 * x.decimal : Floating point number parameter
 * x.str     : String parameter pointer
 * next      : Pointer to next parameter
 *---------------------------------------------------------------------------*/

typedef struct api_ui_param
{
    API_UI_PARAM_TYPE type;

    union
    {
        int value;
        float decimal;
        char* str;
    } x;

    struct api_ui_param* next;
} API_UI_PARAM;

/*
 * UI Handler Definition
 */
typedef char* (*API_UI_HANDLER)(API_UI_PARAM*);
/*
 * String handler for api_ui_printf
 */
typedef int (*API_UI_PRINTF_HANDLER)(const char*,...);


#define      API_UI_ROOT_NODE          ((UINT32) 0)
#define      API_UI_SUB_NODE           ((UINT32) 1)
#define      API_UI_LEAF               ((UINT32) 2)

typedef UINT32 API_UI_NODE_TYPE;

typedef struct api_ui_node API_UI_NODE;

typedef union
{
    API_UI_NODE*        next;
    API_UI_HANDLER      handler;
} API_UI_CHILD;

struct api_ui_node
{
    API_UI_NODE_TYPE      type;
    API_UI_NODE*          right;
    API_UI_CHILD          child;
    API_UI_ELEM*          element;
    API_UI_SECURITY_LEVEL security_level;
};

typedef struct api_ui_cnode
{
    API_UI_NODE**        node_ptr;
    struct api_ui_cnode* next;
} API_UI_CNODE;

#define      CMD_PROC_INIT_STATE           ((UINT32) 0)
#define      CMD_PROC_EXEC_STATE           ((UINT32) 1)

typedef UINT32 API_UI_STATE;

typedef struct api_ui_history
{
    API_UI_ELEM*           element;
    struct api_ui_history* next;
} API_UI_HISTORY;

typedef struct api_ui_instance
{
    EC_BOOL          interactive;   /* Local or remote execution */
    API_UI_STATE    state;    /* State... just because */
    API_UI_PARAM*   params;  /* Keep all of the parameters to be used by handler */
    /*API_UI_HISTORY* history;*/   /* Keep track of what was entered */
    API_UI_NODE*    current;  /* Keep track of where we are in the command tree */
} API_UI_INSTANCE;


#endif  /* _API_UI_INC */

#ifdef __cplusplus
}
#endif /* _cplusplus */

