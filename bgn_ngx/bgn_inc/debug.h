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

#ifndef _DEBUG_H
#define _DEBUG_H

#include "type.h"
#include "mm.h"

#include "bgnctrl.h"

#define DBG_EOF 0xFFFFFFFE

/*max number of supported functions for debug purpose or X-ray purpose*/
#define MAX_NUM_OF_FUNC_FOR_DBG 1024

#define MAX_NUM_OF_FUNC_PARAS   (16)
#define EMB_NUM_OF_FUNC_PARAS   ((UINT32)-1) /*to mark the embed user interface*/

#define MAX_SIZE_OF_FUNC_NAME           128     /* max size of function name in bytes */
#if ( 255 < MAX_SIZE_OF_FUNC_NAME )
#error "debug.h: MAX_SIZE_OF_FUNC_NAME must be less than 256!\n"
#endif

#define DBG_ISSPACE(c) (( ' ' == (c) || '\n' == (c) || '\t' == (c) || '\f' == (c) || '\v' == (c) || '\r' == (c))?EC_TRUE : EC_FALSE)

/*E_DBG_TYPE*/
#define                     e_dbg_UINT32    ((UINT32)  0)
#define                     e_dbg_UINT16    ((UINT32)  1)
#define                      e_dbg_UINT8    ((UINT32)  2)
#define                        e_dbg_int    ((UINT32)  3)
#define                       e_dbg_void    ((UINT32)  4)

#define                    e_dbg_EC_BOOL    ((UINT32)  5)
#define                 e_dbg_UINT32_ptr    ((UINT32)  6)
#define                 e_dbg_UINT16_ptr    ((UINT32)  7)
#define                  e_dbg_UINT8_ptr    ((UINT32)  8)
#define                    e_dbg_int_ptr    ((UINT32)  9)
#define                   e_dbg_void_ptr    ((UINT32) 10)
#define                   e_dbg_REAL_ptr    ((UINT32) 11)
#define                e_dbg_MOD_MGR_ptr    ((UINT32) 12)
#define                e_dbg_CSTRING_ptr    ((UINT32) 13)
#define              e_dbg_TASKC_MGR_ptr    ((UINT32) 14)
#define                    e_dbg_LOG_ptr    ((UINT32) 15)
#define                e_dbg_CVECTOR_ptr    ((UINT32) 17)
#define                  e_dbg_KBUFF_ptr    ((UINT32) 19)
#define          e_dbg_CSOCKET_CNODE_ptr    ((UINT32) 24)
#define             e_dbg_TASKC_NODE_ptr    ((UINT32) 25)
#define          e_dbg_CSYS_CPU_STAT_ptr    ((UINT32) 26)
#define     e_dbg_MM_MAN_OCCUPY_NODE_ptr    ((UINT32) 27)
#define       e_dbg_MM_MAN_LOAD_NODE_ptr    ((UINT32) 28)
#define            e_dbg_MM_MOD_NODE_ptr    ((UINT32) 29)
#define      e_dbg_CPROC_MODULE_STAT_ptr    ((UINT32) 30)
#define      e_dbg_CRANK_THREAD_STAT_ptr    ((UINT32) 31)
#define          e_dbg_CSYS_ETH_STAT_ptr    ((UINT32) 32)
#define          e_dbg_CSYS_DSK_STAT_ptr    ((UINT32) 33)
#define       e_dbg_TASK_REPORT_NODE_ptr    ((UINT32) 34)
#define           e_dbg_CDFSNP_FNODE_ptr    ((UINT32) 35)
#define            e_dbg_CDFSNP_ITEM_ptr    ((UINT32) 36)
#define            e_dbg_CDFSDN_STAT_ptr    ((UINT32) 37)
#define             e_dbg_CLOAD_STAT_ptr    ((UINT32) 38)
#define             e_dbg_CLOAD_NODE_ptr    ((UINT32) 39)
#define              e_dbg_CLOAD_MGR_ptr    ((UINT32) 40)
#define          e_dbg_CDFSDN_RECORD_ptr    ((UINT32) 41)
#define           e_dbg_CDFSDN_BLOCK_ptr    ((UINT32) 42)
#define                 e_dbg_CBYTES_ptr    ((UINT32) 43)
#define               e_dbg_MOD_NODE_ptr    ((UINT32) 44)
#define                 e_dbg_CTIMET_ptr    ((UINT32) 45)
#define          e_dbg_CSESSION_NODE_ptr    ((UINT32) 46)
#define          e_dbg_CSESSION_ITEM_ptr    ((UINT32) 47)
#define                 e_dbg_CSWORD_ptr    ((UINT32) 48)
#define                  e_dbg_CSDOC_ptr    ((UINT32) 49)
#define            e_dbg_CSDOC_WORDS_ptr    ((UINT32) 50)
#define            e_dbg_CSWORD_DOCS_ptr    ((UINT32) 51)
#define                  e_dbg_CLIST_ptr    ((UINT32) 52)
#define            e_dbg_CRFSNP_ITEM_ptr    ((UINT32) 53)
#define           e_dbg_CRFSNP_FNODE_ptr    ((UINT32) 54)
#define            e_dbg_CHFSNP_ITEM_ptr    ((UINT32) 55)
#define           e_dbg_CHFSNP_FNODE_ptr    ((UINT32) 56)
#define               e_dbg_uint64_t_ptr    ((UINT32) 57)
#define      e_dbg_CRFSDN_CACHE_NODE_ptr    ((UINT32) 58)
#define            e_dbg_CMD5_DIGEST_ptr    ((UINT32) 59)
#define                 e_dbg_CRFSOP_ptr    ((UINT32) 60)
#define           e_dbg_CRFSDT_PNODE_ptr    ((UINT32) 61)
#define                e_dbg_CBUFFER_ptr    ((UINT32) 62)
#define                 e_dbg_CSTRKV_ptr    ((UINT32) 63)
#define             e_dbg_CSTRKV_MGR_ptr    ((UINT32) 64)
#define              e_dbg_CHTTP_REQ_ptr    ((UINT32) 65)
#define              e_dbg_CHTTP_RSP_ptr    ((UINT32) 66)
#define             e_dbg_CHTTP_STAT_ptr    ((UINT32) 67)
#define            e_dbg_CHTTP_STORE_ptr    ((UINT32) 68)
#define             e_dbg_TASKS_NODE_ptr    ((UINT32) 69)
#define              e_dbg_CRFS_NODE_ptr    ((UINT32) 70)
#define              e_dbg_CHFS_NODE_ptr    ((UINT32) 71)
#define              e_dbg_CSFS_NODE_ptr    ((UINT32) 72)
#define            e_dbg_CSFSNP_ITEM_ptr    ((UINT32) 73)
#define           e_dbg_CSFSNP_FNODE_ptr    ((UINT32) 74)
#define       e_dbg_CTDNSSV_NODE_MGR_ptr    ((UINT32) 75)
#define           e_dbg_CTDNSSV_NODE_ptr    ((UINT32) 76)
#define              e_dbg_CP2P_FILE_ptr    ((UINT32) 77)
#define               e_dbg_CP2P_CMD_ptr    ((UINT32) 78)
#define             e_dbg_CRFSNP_KEY_ptr    ((UINT32) 79)
#define                   e_dbg_type_end    ((UINT32)128)

/* description of E_DBG_TYPE */
typedef struct
{
    UINT32       dbg_type_value;
    const UINT8 *dbg_type_desc;
}DBG_TYPE_DESC;

/*E_FUNC_PARA_DIRECTION*/
#define                      E_DIRECT_IN    ((UINT32)  0) /*means it is an input parameter*/
#define                     E_DIRECT_OUT    ((UINT32)  1) /*means it is an output parameter*/
#define                      E_DIRECT_IO    ((UINT32)  2) /*means it is an input & output parameter*/
#define                     E_DIRECT_END    ((UINT32)  3)

typedef struct
{
    UINT32  func_module;        /* the module includes this function*/
    UINT32  func_logic_addr;    /* function logical addr in code segment.note: func_logic_addr must be equal to func_beg_addr. */
    UINT32  func_beg_addr;      /* function beg addr in code segment. note: func_beg_addr must be equal to func_logic_addr */
    UINT32  func_end_addr;      /* function end addr in code segment. */
    UINT32  func_addr_offset;   /* function addr offset.Here, func_end_addr = func_beg_addr + func_addr_offset*/
    UINT8   func_name[ MAX_SIZE_OF_FUNC_NAME ];    /* function name */
    UINT32  func_index;         /* function unique index */
    UINT32  func_ret_type;      /* function return type*/
    UINT32  func_para_num;      /* number of function parameters */
    UINT32  func_para_direction[ MAX_NUM_OF_FUNC_PARAS ];/*function parameter direction(IN or OUT)*/
    UINT32  func_para_type[ MAX_NUM_OF_FUNC_PARAS ];     /*function parameter type list*/

    UINT32  func_ret_value;     /* function return value */
    UINT32  func_retval_addr;   /* addr of func return value */
    UINT32  func_para_value[ MAX_NUM_OF_FUNC_PARAS ]; /* function parameter value list. used by task.c */
                                /* if para is pointer, the value = addr of para */
                                /* if para is not pointer, the value = para */
}FUNC_ADDR_NODE;

typedef struct
{
    UINT32 func_num;    /*total number of func addr nodes in this block*/
    FUNC_ADDR_NODE *func_addr_node[MAX_NUM_OF_FUNC_FOR_DBG]; /*func addr node table in this block*/
}FUNC_ADDR_BLOCK;

typedef void * (*dbg_md_fget_mod_mgr)(const UINT32);

typedef struct
{
    UINT32          md_type;
    UINT32         *func_num;
    FUNC_ADDR_NODE *func_addr_node;

    UINT32      md_start_func_id;
    UINT32      md_end_func_id;
    UINT32      md_set_mod_mgr_func_id;
    dbg_md_fget_mod_mgr md_fget_mod_mgr;
}FUNC_ADDR_MGR;

#define FUNC_ADDR_MGR_MD_TYPE(func_addr_mgr)                ((func_addr_mgr)->md_type)
#define FUNC_ADDR_MGR_FUNC_NUM_PTR(func_addr_mgr)           ((func_addr_mgr)->func_num)
#define FUNC_ADDR_MGR_FUNC_ADDR_NODE(func_addr_mgr)         ((func_addr_mgr)->func_addr_node)
#define FUNC_ADDR_MGR_MD_START_FUNC_ID(func_addr_mgr)       ((func_addr_mgr)->md_start_func_id)
#define FUNC_ADDR_MGR_MD_END_FUNC_ID(func_addr_mgr)         ((func_addr_mgr)->md_end_func_id)
#define FUNC_ADDR_MGR_MD_SET_MOD_FUNC_ID(func_addr_mgr)     ((func_addr_mgr)->md_set_mod_mgr_func_id)
#define FUNC_ADDR_MGR_MD_GET_MOD_FUNC_ID(func_addr_mgr)     ((func_addr_mgr)->md_fget_mod_mgr)

/*function parameter item definition*/
/*used by autotest.c and task.c*/
typedef struct
{
    UINT32  func_para_direction;/*direction = E_DIRECT_IN  means this is an input parameter*/
                                /*direction = E_DIRECT_OUT means this is an output parameter*/
    UINT32  func_para_type;     /*take value of E_DBG_TYPE*/
    UINT32  func_para_value;    /*parameter value: if the type is value, then it's the value*/
                                /*if the type is pointer, then it's the address*/
}FUNC_PARA_ITEM;

/*function parameter list definition*/
/*used by autotest.c and task.c*/
typedef struct
{
    UINT32 func_para_num; /* the number of parameters*/
    FUNC_PARA_ITEM para_item[MAX_NUM_OF_FUNC_PARAS];/*parameter list*/
}FUNC_PARA_LIST;

typedef struct
{
    UINT32     type;               /* the type of variable, range: E_DBG_TYPE */
    UINT32     type_sizeof;        /* the type sizeof. if type is pointer, it should be sizeof(UINT32) */
    EC_BOOL    pointer_flag;       /* if type is pointer, then flag = EC_TRUE; otherwise, flag = EC_FALSE */
    EC_BOOL    md_id_flag;         /* if type is module id, then flag = EC_TRUE; otherwise, flag = EC_FALSE */
    UINT32     var_mm_type;        /* the variable memory allocated for this variable. range: MM_TYPE */
    UINT32     str_mm_type;        /* the char buf memory allocated to accept the string format of this variable */
    UINT32     str_mm_size;        /* the num bytes of str_mm_type */
    UINT32     init_type_func;     /* initialize the type variable. NOTE: set to zero if the var type is basic, such as UINT32, UINT16, etc.*/
    UINT32     clean_type_func;    /* clean the type variable without destroy the variable itself. NOTE: set to zero if the var type is basic, such as UINT32, UINT16, etc.*/
    UINT32     free_type_func;     /* free the type variable with destroy the variable itself. NOTE: set to zero if the var type is basic, such as UINT32, UINT16, etc.*/
    UINT32     print_type_to_hex_func; /* print this type var out to hex format */
    UINT32     print_type_to_dec_func; /* print this type var out to bin format */
    UINT32     conv_type_to_dec_func;  /* convert this type var to dec string */
    UINT32     conv_type_to_hex_func;  /* convert this type var to hex string */
    UINT32     conv_type_to_bin_func;  /* convert this type var to bin string */
    UINT32     dec_conv_to_type_func;  /* convert dec string to this type var */
    UINT32     hex_conv_to_type_func;  /* convert hex string to this type var */
    UINT32     bin_conv_to_type_func;  /* convert hex string to this type var */
    UINT32     cmpi_encode_type_func;  /* CMPI Encode type to string          */
    UINT32     cmpi_decode_type_func;  /* CMPI Decode type to string          */
    UINT32     cmpi_encode_type_size;  /* string size of CMPI Encode type     */
}TYPE_CONV_ITEM;

#define TYPE_CONV_ITEM_VAR_DBG_TYPE(type_conv_item)                 ((type_conv_item)->type)
#define TYPE_CONV_ITEM_VAR_SIZEOF(type_conv_item)                   ((type_conv_item)->type_sizeof)
#define TYPE_CONV_ITEM_VAR_POINTER_FLAG(type_conv_item)             ((type_conv_item)->pointer_flag)
#define TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item)                  ((type_conv_item)->var_mm_type)
#define TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item)                ((type_conv_item)->init_type_func)
#define TYPE_CONV_ITEM_VAR_CLEAN_FUNC(type_conv_item)               ((type_conv_item)->clean_type_func)
#define TYPE_CONV_ITEM_VAR_FREE_FUNC(type_conv_item)                ((type_conv_item)->free_type_func)
#define TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item)              ((type_conv_item)->cmpi_encode_type_func)
#define TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item)              ((type_conv_item)->cmpi_decode_type_func)
#define TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item)              ((type_conv_item)->cmpi_encode_type_size)

/*function prototype definition used by caller without assembler*/
/*note 1: all parameters must be UINT32*/
/*note 2: support max to 16 parameters*/
#if (16 != MAX_NUM_OF_FUNC_PARAS)
#error "fatal error:debug.h: MAX_NUM_OF_FUNC_PARAS != 16"
#endif

#define TP UINT32
typedef TP (*FUNC_TYPE_0 )();
typedef TP (*FUNC_TYPE_1 )(TP);
typedef TP (*FUNC_TYPE_2 )(TP, TP);
typedef TP (*FUNC_TYPE_3 )(TP, TP, TP);
typedef TP (*FUNC_TYPE_4 )(TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_5 )(TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_6 )(TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_7 )(TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_8 )(TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_9 )(TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_10)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_11)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_12)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_13)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_14)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_15)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
typedef TP (*FUNC_TYPE_16)(TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP, TP);
#undef TP


/*regard the value as a certain pointer*/
#define N_REGARD_VAL_AS_PTR(val) ((void *)(val))

/*regard the value as a certain type pointer*/
#define N_REGARD_VAL_AS_TYPE_PTR(type, type_val) ((type *)(type_val))

/* get the certain type value from a address which point to the tyep value */
#define N_GET_TYPE_VAL_FROM_TYPE_PTR(type, type_ptr) ( (type)(*(type_ptr)) )

#define N_GET_RET_CODE_ADDRESS(reg_ebp)  \
    N_GET_TYPE_VAL_FROM_TYPE_PTR(UINT32, N_REGARD_VAL_AS_TYPE_PTR(UINT32, reg_ebp + 4) )

#define N_GET_RET_FUNC_EBP(reg_ebp)      \
    N_GET_TYPE_VAL_FROM_TYPE_PTR(UINT32, N_REGARD_VAL_AS_TYPE_PTR(UINT32, reg_ebp) )

/*para_no : parameter No. in the parameters from left to right ,range[0,1,2,...] */
#define N_GET_PARA_STACK_POS(reg_ebp, para_no)       ((reg_ebp) + 8 + 4 * (para_no))

/*since the function stack always push anything into the parameter stack aligned by 4-bytes, so*/
/*what is taken out from the parameter stack is always a 4-bytes value*/
#define N_GET_VAL_FROM_PARA_STACK_POS(para_stack_pos) (*(UINT32 *)(para_stack_pos))

/*the value taken from parameter stack is just the desired paramter value*/
/*get non-ptr parameter value*/
#define N_GET_NON_PTR_PARA_VAL_BY_PARA_STACK_POS(para_type, para_stack_pos)    \
    (para_type N_GET_VAL_FROM_PARA_STACK_POS(para_stack_pos))

/*the value taken from parameter stack is just a pointer which point to the desired paramter value*/
/*get a pointer which point to the parameter value and the pointer itself is stored in the parameter stack*/
#define N_GET_PTR_PARA_VAL_BY_PARA_STACK_POS(para_type, para_stack_pos) \
    (para_type* N_GET_VAL_FROM_PARA_STACK_POS(para_stack_pos))

#define ERR_FUNC_LOGIC_ADDR  (~((UINT32)0))
#define ERR_FUNC_REAL_ADDR  (~((UINT32)0))

#define dbg_start(mysql_acc, entry_func_logic_addr, entry_func_name) do{}while(0)


FUNC_ADDR_MGR * dbg_fetch_func_addr_mgr_by_md_type(const UINT32 md_type);

UINT32 dbg_fetch_func_addr_node_by_index(UINT32 func_index, FUNC_ADDR_NODE **func_addr_node_ret);

UINT32 dbg_register_func_addr_list(const FUNC_ADDR_NODE *func_addr_node_list, const UINT32 func_addr_node_list_len,FUNC_ADDR_BLOCK *func_addr_block);

EC_BOOL dbg_fetch_func_addr( const UINT8 * srv_host, const UINT8 * srv_port, FUNC_ADDR_BLOCK *func_addr_block );


void   dbg_exit( UINT32  module_type,UINT32  module_id);

/*called by autotest.c*/
EC_BOOL dbg_str_cmp(const UINT8 *str_1, const UINT8 * str_2);

/*called by autotest.c*/
/*get module priority by index*/
UINT32 dbg_get_mod_prio_by_index(const UINT32 func_index, UINT32 *mod_prio);

/*called by autotest.c*/
UINT32 dbg_get_func_name_by_index(const UINT32 func_index,const UINT8 **func_name);

/*called by autotest.c*/
UINT32 dbg_get_func_index_by_name(const UINT8 *func_name, UINT32 *func_index);

/*called by autotest.c*/
UINT32 dbg_get_func_ret_type_by_index(UINT32 func_index, UINT32 *func_ret_type);

/*called by autotest.c*/
UINT32 dbg_get_func_para_type_by_index(UINT32 func_index, FUNC_PARA_LIST *func_para_list);

/*called by autotest.c*/
UINT32 dbg_get_func_real_addr_by_index(UINT32 func_index, UINT32 *func_real_addr);

/*called by autotest.c*/
EC_BOOL dbg_func_ret_value_cmp(LOG *log,UINT32 ret_type, UINT32 db_naked_ret_value,UINT32 ret_naked_ret_value);

/*called by autotest.c*/
EC_BOOL dbg_func_para_value_cmp(LOG *log,UINT32 para_type, UINT32 db_naked_para_value,UINT32 ret_naked_para_value);

/**
*   called by autotest.c
*   get one char which is excluded comments from the file
**/
UINT32 dbg_get_one_char_from_file(FILE *file, UINT8 *ch);
/**
*   called by autotest.c
*   read a string from the file.
*   comment will be skipped and any space char will terminate the string
**/
UINT32 dbg_get_one_str_from_file(FILE *log, UINT8 *desstr, UINT32 maxlen,UINT32 *retlen);

TYPE_CONV_ITEM * dbg_query_type_conv_item_by_type(const UINT32 type);

TYPE_CONV_ITEM * dbg_query_type_conv_item_by_mm(const UINT32 var_mm_type);

UINT32  dbg_tiny_caller(const UINT32 func_para_num, const UINT32 func_addr, ...);

EC_BOOL dbg_caller(const UINT32 func_addr, const UINT32 func_para_num, UINT32 *func_para_value, UINT32 *func_ret_val);

/**
*
* init UINT32
*
**/
UINT32 dbg_init_uint32_ptr(UINT32 *num);

/**
*
* init UINT32
*
**/
UINT32 dbg_clean_uint32_ptr(UINT32 *num);

/**
*
* free UINT32
*
**/
UINT32 dbg_free_uint32_ptr(UINT32 *num);

/**
*
* init uint64_t
*
**/
uint64_t dbg_init_uint64_ptr(uint64_t *num);

/**
*
* init uint64_t
*
**/
uint64_t dbg_clean_uint64_ptr(uint64_t *num);
/**
*
* free uint64_t
*
**/
uint64_t dbg_free_uint64_ptr(uint64_t *num);

#endif /*_DEBUG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

