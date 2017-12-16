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

#ifndef _API_CMD_INC
#define _API_CMD_INC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "cstring.h"
#include "log.h"

#define API_CMD_SEG_WORD_SIZE                    ((UINT32) 64)

#define       CMD_SEG_TYPE_NULL                  ((UINT32) 0)
#define       CMD_SEG_TYPE_KEYWORD               ((UINT32) 1) /*normal word string*/
#define       CMD_SEG_TYPE_LIST                  ((UINT32) 2) /*%l*/
#define       CMD_SEG_TYPE_LIST_ITEM             ((UINT32) 3) /**/
#define       CMD_SEG_TYPE_RANGE                 ((UINT32) 4) /*%r*/
#define       CMD_SEG_TYPE_INTEGER               ((UINT32) 5) /*%n*/
#define       CMD_SEG_TYPE_REAL                  ((UINT32) 6) /*%f*/
#define       CMD_SEG_TYPE_CSTRING               ((UINT32) 7) /*%s*/
#define       CMD_SEG_TYPE_TCID                  ((UINT32) 8) /*%t*/
#define       CMD_SEG_TYPE_MASK                  ((UINT32) 9) /*%m*/
#define       CMD_SEG_TYPE_IPADDR                ((UINT32)10) /*%p*/
#define       CMD_SEG_TYPE_UINT64                ((UINT32)11) /*%N*/

#define       CMD_PARA_TYPE_NULL                 ((UINT32) 0)
#define       CMD_PARA_TYPE_INTEGER              ((UINT32) 1)
#define       CMD_PARA_TYPE_REAL                 ((UINT32) 2)
#define       CMD_PARA_TYPE_CSTRING              ((UINT32) 3)
#define       CMD_PARA_TYPE_LIST                 ((UINT32) 4)
#define       CMD_PARA_TYPE_LIST_ITEM            ((UINT32) 5)
#define       CMD_PARA_TYPE_TCID                 ((UINT32) 6)
#define       CMD_PARA_TYPE_MASK                 ((UINT32) 7)
#define       CMD_PARA_TYPE_IPADDR               ((UINT32) 8)

typedef CVECTOR CMD_ELEM_VEC;
#define CMD_ELEM_NODE_VEC(cmd_elem_vec)          (cmd_elem_vec)

typedef struct
{
    UINT8  cmd_elem_word[ API_CMD_SEG_WORD_SIZE ];
    UINT32 cmd_elem_type;
    union
    {
        UINT32    uint32;
        uint64_t  uint64;
        REAL      real;
        CSTRING  *cstring;
        CVECTOR  *vec;/*cmd elem vec*/
    }u;
}CMD_ELEM;

#define CMD_ELEM_WORD(this_cmd_elem)                 ((this_cmd_elem)->cmd_elem_word)
#define CMD_ELEM_WORD_CHAR(this_cmd_elem, pos)       ((this_cmd_elem)->cmd_elem_word[ (pos) ])
#define CMD_ELEM_TYPE(this_cmd_elem)                 ((this_cmd_elem)->cmd_elem_type)
#define CMD_ELEM_UINT32(this_cmd_elem)               ((this_cmd_elem)->u.uint32)
#define CMD_ELEM_UINT64(this_cmd_elem)               ((this_cmd_elem)->u.uint64)
#define CMD_ELEM_REAL(this_cmd_elem)                 ((this_cmd_elem)->u.real)
#define CMD_ELEM_CSTRING(this_cmd_elem)              ((this_cmd_elem)->u.cstring)
#define CMD_ELEM_VEC(this_cmd_elem)                  ((this_cmd_elem)->u.vec)


typedef CLIST CMD_TREE;
#define CMD_TREE_SEG_LIST(cmd_tree)                (cmd_tree)

typedef CVECTOR CMD_PARA_VEC;
#define CMD_PARA_VAL_LIST(cmd_para_vec)            (cmd_para_vec)

typedef EC_BOOL (*CMD_HANDLER)(CMD_PARA_VEC *);

typedef struct
{
    UINT8  cmd_seg_word[ API_CMD_SEG_WORD_SIZE ];
    UINT32 cmd_seg_type;

    CMD_ELEM    *cmd_elem;

    CMD_TREE    *cmd_seg_subtree;/*list of next cmd seg*/
    CMD_HANDLER  cmd_seg_handler;
}CMD_SEG;

#define CMD_SEG_WORD(this_cmd_seg)                  ((this_cmd_seg)->cmd_seg_word)
#define CMD_SEG_WORD_CHAR(this_cmd_seg, pos)        ((this_cmd_seg)->cmd_seg_word[(pos)])
#define CMD_SEG_WORD_CHAR_PTR(this_cmd_seg, pos)    (&(CMD_SEG_WORD_CHAR(this_cmd_seg, pos)))
#define CMD_SEG_TYPE(this_cmd_seg)                  ((this_cmd_seg)->cmd_seg_type)
#define CMD_SEG_ELEM(this_cmd_seg)                  ((this_cmd_seg)->cmd_elem)
#define CMD_SEG_SUB_TREE(this_cmd_seg)              ((this_cmd_seg)->cmd_seg_subtree)
#define CMD_SEG_HANDLER(this_cmd_seg)               ((this_cmd_seg)->cmd_seg_handler)

typedef struct
{
    UINT32 cmd_para_type;

    union
    {
        UINT32    uint32;
        REAL      real;
        CSTRING  *cstring;
        uint64_t  uint64;
    }u;
}CMD_PARA;

#define CMD_PARA_TYPE(this_cmd_para)               ((this_cmd_para)->cmd_para_type)
#define CMD_PARA_UINT32(this_cmd_para)             ((this_cmd_para)->u.uint32)
#define CMD_PARA_REAL(this_cmd_para)               ((this_cmd_para)->u.real)
#define CMD_PARA_CSTRING(this_cmd_para)            ((this_cmd_para)->u.cstring)
#define CMD_PARA_UINT64(this_cmd_para)             ((this_cmd_para)->u.uint64)

typedef CVECTOR CMD_HELP_VEC;
#define CMD_HELP_NODE_VEC(cmd_help_vec)            (cmd_help_vec)

typedef struct
{
    UINT8 *cmd_help_abbr;
    UINT8 *cmd_help_syntax;
}CMD_HELP;

#define CMD_HELP_ABBR(this_cmd_help)        ((this_cmd_help)->cmd_help_abbr)
#define CMD_HELP_SYNTAX(this_cmd_help)      ((this_cmd_help)->cmd_help_syntax)

#endif/*_API_CMD_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
