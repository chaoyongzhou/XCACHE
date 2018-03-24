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
#include <stdarg.h>
#include <pthread.h>

#include "type.h"

#include "log.h"
#include "bgnctrl.h"

#include "mm.h"

#include "debug.h"

#include "cthread.h"
#include "creg.h"
#include "coroutine.h"

/**
*
*     query the type_conv_item of specific type
*
*
**/
TYPE_CONV_ITEM * dbg_query_type_conv_item_by_type(const UINT32 type)
{
    return creg_type_conv_vec_get(creg_type_conv_vec_fetch(), type);
}

/**
*
*     query the type_conv_item of specific mm type
*
*
**/
TYPE_CONV_ITEM * dbg_query_type_conv_item_by_mm(const UINT32 var_mm_type)
{
    CVECTOR *type_conv_vec;
    UINT32 var_dbg_type;

    type_conv_vec = creg_type_conv_vec_fetch();
    if(NULL_PTR == type_conv_vec)
    {
        dbg_log(SEC_0047_DEBUG, 0)(LOGSTDOUT, "error:dbg_query_type_conv_item_by_mm: fetch type conv vec failed\n");
        return (NULL_PTR);
    }

    for(var_dbg_type = 0; var_dbg_type < cvector_size(type_conv_vec); var_dbg_type ++)
    {
        TYPE_CONV_ITEM *type_conv_item;;

        type_conv_item = creg_type_conv_vec_get(type_conv_vec, var_dbg_type);
        if(NULL_PTR == type_conv_item)
        {
            continue;
        }
        if(var_mm_type == TYPE_CONV_ITEM_VAR_MM_TYPE(type_conv_item))
        {
            return (type_conv_item);
        }
    }
    return (NULL_PTR);
}


/**
*
* dbg tiny caller forge a calling scenario who push paras into stack and push out after come back
*
*
**/
#if (32 == WORDSIZE)
UINT32 dbg_tiny_caller(const UINT32 func_para_num, const UINT32 func_addr, ...)
{
    UINT32 func_para_value[ MAX_NUM_OF_FUNC_PARAS ];
    UINT32 func_ret_value;
    UINT32 esp_offset;
    UINT32 index;

    va_list ap;

    if(0 == func_addr)
    {
        return (0);
    }

    va_start(ap, func_addr);
    for( index = 0; index < func_para_num; index ++ )
    {
        func_para_value[ index ] = va_arg(ap, UINT32);
    }
    va_end(ap);

    /*call the function and restore the stack after its return*/
    /*the return value should be returned by EAX register*/
    esp_offset = (func_para_num) * (WORDSIZE/BYTESIZE);

    //sys_print(LOGSTDOUT,"task_tiny_caller: before calling...\n");
    /*if one PUSH operation occurs in the loop and out of the asm scope, then corrupt!*/
    /*push the parameters of the function from right to left one by one*/
    /*for example, if function is defined as void add(int a, int b,int *c), then do*/
    /* push c */
    /* push b*/
    /* push a*/
    for( index = func_para_num; index > 0; )
    {
        index --;
        __asm__ __volatile__
        (
                "pushl %0;"
        :
        :"im"(func_para_value[ index ])
        :"memory"
        );
    }

    /* IMPORTANT: here all values are transferred to assembler via memory style */
    /* due to the observation of anti-assembler shows the registers are not organized very well, */
    /* and some time it is even far wrong! */
       __asm__ __volatile__
       (
            "call %1;"
            "movl %%eax, %0;"
            "addl %2, %%esp;"
            :"=m"(func_ret_value)
            :"im"(func_addr),"im"(esp_offset)
    :"memory"
       );

    //sys_print(LOGSTDOUT,"dbg_tiny_caller: after calling, func_ret_value = %lx\n", func_ret_value);

    return ( func_ret_value );
}
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
UINT32 dbg_tiny_caller(const UINT32 func_para_num, const UINT32 func_addr, ...)
{
    /* ================WARNING: DO NOT INSERT ANY CODE HERE: beg ===========================================*/
    UINT32 func_para_value[ MAX_NUM_OF_FUNC_PARAS ];
    UINT32 func_ret_value;
    UINT32 index;

    va_list ap;

    if(0 == func_addr)
    {
        return (0);
    }

    //dbg_log(SEC_0047_DEBUG, 5)(LOGSTDOUT, "dbg_tiny_caller: func_addr = %lx, func_para_num = %d\n", func_addr, func_para_num);
    va_start(ap, func_addr);
    for( index = 0; index < func_para_num; index ++ )
    {
        func_para_value[ index ] = va_arg(ap, UINT32);
        //dbg_log(SEC_0047_DEBUG, 5)(LOGSTDOUT, "dbg_tiny_caller: func para no %d: %lx\n", index, func_para_value[ index ]);
    }
    va_end(ap);

#if (16 != MAX_NUM_OF_FUNC_PARAS)
#error "fatal error:debug.c: MAX_NUM_OF_FUNC_PARAS != 16"
#endif
    #define PARA_VALUE(func_para, x)    ((func_para)[ (x) ])

    #define PARA_LIST_0(func_para)    /*no parameter*/
    #define PARA_LIST_1(func_para)    PARA_VALUE(func_para, 0)
    #define PARA_LIST_2(func_para)    PARA_LIST_1(func_para) ,PARA_VALUE(func_para, 1)
    #define PARA_LIST_3(func_para)    PARA_LIST_2(func_para) ,PARA_VALUE(func_para, 2)
    #define PARA_LIST_4(func_para)    PARA_LIST_3(func_para) ,PARA_VALUE(func_para, 3)
    #define PARA_LIST_5(func_para)    PARA_LIST_4(func_para) ,PARA_VALUE(func_para, 4)
    #define PARA_LIST_6(func_para)    PARA_LIST_5(func_para) ,PARA_VALUE(func_para, 5)
    #define PARA_LIST_7(func_para)    PARA_LIST_6(func_para) ,PARA_VALUE(func_para, 6)
    #define PARA_LIST_8(func_para)    PARA_LIST_7(func_para) ,PARA_VALUE(func_para, 7)
    #define PARA_LIST_9(func_para)    PARA_LIST_8(func_para) ,PARA_VALUE(func_para, 8)
    #define PARA_LIST_10(func_para)   PARA_LIST_9(func_para) ,PARA_VALUE(func_para, 9)
    #define PARA_LIST_11(func_para)   PARA_LIST_10(func_para),PARA_VALUE(func_para, 10)
    #define PARA_LIST_12(func_para)   PARA_LIST_11(func_para),PARA_VALUE(func_para, 11)
    #define PARA_LIST_13(func_para)   PARA_LIST_12(func_para),PARA_VALUE(func_para, 12)
    #define PARA_LIST_14(func_para)   PARA_LIST_13(func_para),PARA_VALUE(func_para, 13)
    #define PARA_LIST_15(func_para)   PARA_LIST_14(func_para),PARA_VALUE(func_para, 14)
    #define PARA_LIST_16(func_para)   PARA_LIST_15(func_para),PARA_VALUE(func_para, 15)

    #define FUNC_CALL(x, func_addr, func_para) \
            ((FUNC_TYPE_##x) func_addr)(PARA_LIST_##x(func_para))

    switch(func_para_num)
    {
        case 0:
            func_ret_value = FUNC_CALL(0, func_addr, func_para_value);
            break;
        case 1:
            func_ret_value = FUNC_CALL(1, func_addr, func_para_value);
            break;
        case 2:
            func_ret_value = FUNC_CALL(2, func_addr, func_para_value);
            break;
        case 3:
            func_ret_value = FUNC_CALL(3, func_addr, func_para_value);
            break;
        case 4:
            func_ret_value = FUNC_CALL(4, func_addr, func_para_value);
            break;
        case 5:
            func_ret_value = FUNC_CALL(5, func_addr, func_para_value);
            break;
        case 6:
            func_ret_value = FUNC_CALL(6, func_addr, func_para_value);
            break;
        case 7:
            func_ret_value = FUNC_CALL(7, func_addr, func_para_value);
            break;
        case 8:
            func_ret_value = FUNC_CALL(8, func_addr, func_para_value);
            break;
        case 9:
            func_ret_value = FUNC_CALL(9, func_addr, func_para_value);
            break;
        case 10:
            func_ret_value = FUNC_CALL(10, func_addr, func_para_value);
            break;
        case 11:
            func_ret_value = FUNC_CALL(11, func_addr, func_para_value);
            break;
        case 12:
            func_ret_value = FUNC_CALL(12, func_addr, func_para_value);
            break;
        case 13:
            func_ret_value = FUNC_CALL(13, func_addr, func_para_value);
            break;
        case 14:
            func_ret_value = FUNC_CALL(14, func_addr, func_para_value);
            break;
        case 15:
            func_ret_value = FUNC_CALL(15, func_addr, func_para_value);
            break;
        case 16:
            func_ret_value = FUNC_CALL(16, func_addr, func_para_value);
            break;
        default:
            dbg_log(SEC_0047_DEBUG, 0)(LOGSTDOUT, "error:dbg_tiny_caller: func para num = %d overflow\n", func_para_num);
            return ((UINT32)(-1));
    }

    #undef PARA_VALUE

    #undef PARA_LIST_0
    #undef PARA_LIST_1
    #undef PARA_LIST_2
    #undef PARA_LIST_3
    #undef PARA_LIST_4
    #undef PARA_LIST_5
    #undef PARA_LIST_6
    #undef PARA_LIST_7
    #undef PARA_LIST_8
    #undef PARA_LIST_9
    #undef PARA_LIST_10
    #undef PARA_LIST_11
    #undef PARA_LIST_12
    #undef PARA_LIST_13
    #undef PARA_LIST_14
    #undef PARA_LIST_15
    #undef PARA_LIST_16

    #undef FUNC_CALL

    return ( func_ret_value );
}
#endif/*(64 == WORDSIZE)*/

EC_BOOL dbg_caller(const UINT32 func_addr, const UINT32 func_para_num, UINT32 *func_para_value, UINT32 *func_ret_val)
{
    UINT32 func_ret_value;

#if (16 != MAX_NUM_OF_FUNC_PARAS)
#error "fatal error:debug.c::dbg_caller MAX_NUM_OF_FUNC_PARAS != 16"
#endif
    #define PARA_VALUE(func_para, x)    ((func_para)[ (x) ])

    #define PARA_LIST_0(func_para)    /*no parameter*/
    #define PARA_LIST_1(func_para)    PARA_VALUE(func_para, 0)
    #define PARA_LIST_2(func_para)    PARA_LIST_1(func_para) ,PARA_VALUE(func_para, 1)
    #define PARA_LIST_3(func_para)    PARA_LIST_2(func_para) ,PARA_VALUE(func_para, 2)
    #define PARA_LIST_4(func_para)    PARA_LIST_3(func_para) ,PARA_VALUE(func_para, 3)
    #define PARA_LIST_5(func_para)    PARA_LIST_4(func_para) ,PARA_VALUE(func_para, 4)
    #define PARA_LIST_6(func_para)    PARA_LIST_5(func_para) ,PARA_VALUE(func_para, 5)
    #define PARA_LIST_7(func_para)    PARA_LIST_6(func_para) ,PARA_VALUE(func_para, 6)
    #define PARA_LIST_8(func_para)    PARA_LIST_7(func_para) ,PARA_VALUE(func_para, 7)
    #define PARA_LIST_9(func_para)    PARA_LIST_8(func_para) ,PARA_VALUE(func_para, 8)
    #define PARA_LIST_10(func_para)   PARA_LIST_9(func_para) ,PARA_VALUE(func_para, 9)
    #define PARA_LIST_11(func_para)   PARA_LIST_10(func_para),PARA_VALUE(func_para, 10)
    #define PARA_LIST_12(func_para)   PARA_LIST_11(func_para),PARA_VALUE(func_para, 11)
    #define PARA_LIST_13(func_para)   PARA_LIST_12(func_para),PARA_VALUE(func_para, 12)
    #define PARA_LIST_14(func_para)   PARA_LIST_13(func_para),PARA_VALUE(func_para, 13)
    #define PARA_LIST_15(func_para)   PARA_LIST_14(func_para),PARA_VALUE(func_para, 14)
    #define PARA_LIST_16(func_para)   PARA_LIST_15(func_para),PARA_VALUE(func_para, 15)

    #define FUNC_CALL(x, func_addr, func_para) \
            ((FUNC_TYPE_##x) func_addr)(PARA_LIST_##x(func_para))

    switch(func_para_num)
    {
        case 0:
            func_ret_value = FUNC_CALL(0, func_addr, func_para_value);
            break;
        case 1:
            func_ret_value = FUNC_CALL(1, func_addr, func_para_value);
            break;
        case 2:
            func_ret_value = FUNC_CALL(2, func_addr, func_para_value);
            break;
        case 3:
            func_ret_value = FUNC_CALL(3, func_addr, func_para_value);
            break;
        case 4:
            func_ret_value = FUNC_CALL(4, func_addr, func_para_value);
            break;
        case 5:
            func_ret_value = FUNC_CALL(5, func_addr, func_para_value);
            break;
        case 6:
            func_ret_value = FUNC_CALL(6, func_addr, func_para_value);
            break;
        case 7:
            func_ret_value = FUNC_CALL(7, func_addr, func_para_value);
            break;
        case 8:
            func_ret_value = FUNC_CALL(8, func_addr, func_para_value);
            break;
        case 9:
            func_ret_value = FUNC_CALL(9, func_addr, func_para_value);
            break;
        case 10:
            func_ret_value = FUNC_CALL(10, func_addr, func_para_value);
            break;
        case 11:
            func_ret_value = FUNC_CALL(11, func_addr, func_para_value);
            break;
        case 12:
            func_ret_value = FUNC_CALL(12, func_addr, func_para_value);
            break;
        case 13:
            func_ret_value = FUNC_CALL(13, func_addr, func_para_value);
            break;
        case 14:
            func_ret_value = FUNC_CALL(14, func_addr, func_para_value);
            break;
        case 15:
            func_ret_value = FUNC_CALL(15, func_addr, func_para_value);
            break;
        case 16:
            func_ret_value = FUNC_CALL(16, func_addr, func_para_value);
            break;
        default:
            dbg_log(SEC_0047_DEBUG, 0)(LOGSTDOUT, "error:dbg_caller: func para num = %d overflow\n", func_para_num);
            return (EC_FALSE);
    }

    if(NULL_PTR != func_ret_val)
    {
        (*func_ret_val) = func_ret_value;
    }
    return (EC_TRUE);

    #undef PARA_VALUE

    #undef PARA_LIST_0
    #undef PARA_LIST_1
    #undef PARA_LIST_2
    #undef PARA_LIST_3
    #undef PARA_LIST_4
    #undef PARA_LIST_5
    #undef PARA_LIST_6
    #undef PARA_LIST_7
    #undef PARA_LIST_8
    #undef PARA_LIST_9
    #undef PARA_LIST_10
    #undef PARA_LIST_11
    #undef PARA_LIST_12
    #undef PARA_LIST_13
    #undef PARA_LIST_14
    #undef PARA_LIST_15
    #undef PARA_LIST_16

    #undef FUNC_CALL
}

FUNC_ADDR_MGR * dbg_fetch_func_addr_mgr_by_md_type(const UINT32 md_type)
{
    return creg_func_addr_vec_get(creg_func_addr_vec_fetch(), md_type);
}

UINT32 dbg_fetch_func_addr_node_by_index(UINT32 func_index, FUNC_ADDR_NODE **func_addr_node_ret)
{
    UINT32 func_addr_node_idx;
    UINT32 func_num;
    FUNC_ADDR_MGR *func_addr_mgr;
    FUNC_ADDR_NODE *func_addr_node;

    func_addr_mgr = dbg_fetch_func_addr_mgr_by_md_type(func_index >> (WORDSIZE/2));
    if(NULL_PTR == func_addr_mgr)
    {
        dbg_log(SEC_0047_DEBUG, 0)(LOGSTDOUT, "error:dbg_fetch_func_addr_node_by_index: func index %lx out of range\n", func_index);
        return ((UINT32)(-1));
    }

    func_num = *(func_addr_mgr->func_num);
    func_addr_node_idx = ((func_index << (WORDSIZE/2)) >> (WORDSIZE/2));

    if(func_addr_node_idx < func_num
    && func_index == func_addr_mgr->func_addr_node[ func_addr_node_idx ].func_index)
    {
        func_addr_node = &(func_addr_mgr->func_addr_node[ func_addr_node_idx ]);
        *func_addr_node_ret = func_addr_node;
        return (0);
    }

    for(func_addr_node_idx = 0; func_addr_node_idx < func_num; func_addr_node_idx ++)
    {
        func_addr_node = &(func_addr_mgr->func_addr_node[ func_addr_node_idx ]);
        if(func_index == func_addr_node->func_index)
        {
            *func_addr_node_ret = func_addr_node;
            return (0);
        }
    }

    return ((UINT32)(-2));
}

EC_BOOL dbg_type_is_stru_type(UINT32 type)
{
    switch( type )
    {
            break;

        default:
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


void dbg_exit( UINT32  module_type,UINT32  module_id)
{
    exit( 4 );
#if 0
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    if(CTHREAD_GET_TID() == CTHREAD_FETCH_TID(TASK_BRD_DO_ROUTINE_CTHREAD_ID(task_brd), CTHREAD_TID_OFFSET))
    {
        dbg_log(SEC_0047_DEBUG, 5)(LOGSTDOUT, "dbg_exit: cancel coroutine\n");
        coroutine_cancel();
    }
    else
    {
        CTHREAD_ID cthread_id;

        cthread_id = pthread_self();
        dbg_log(SEC_0047_DEBUG, 5)(LOGSTDOUT, "dbg_exit: cancel thread %u\n", cthread_id);

        /*kill thread self*/
        cthread_cancel(cthread_id);
    }
#endif
}

/*get one char which is excluded comments from the file*/
UINT32 dbg_get_one_char_from_file(FILE *file, UINT8 *ch)
{
    /*when the char '/', then check whether the next char is '*' or not.*/
    /*if the next char is not '*', then store the next char to next_char*/
    /*generally, set next_char = 0xFF to distinguish above.*/
    static UINT8 next_char = 0xFF;

    /*read a char from file and store it to cur_char*/
    int cur_char = 0xEE;

    /*if the next_char is not 0xFF, */
    /*which means that one char is stored in next_char waiting to be read*/
    /*then return this char directly*/
    if ( 0xFF != next_char )
    {
        *ch = next_char;
        next_char = 0xFF;

        return ( 0 );
    }

    /*read a char from file*/
    cur_char = fgetc(file);

    /*if the char is '/' then*/
    if ( '/' == cur_char )
    {
        /*read next char from file and check whether it's '*' */
        cur_char = fgetc(file);

        /*if the char is NOT '*', then we do not enter a comment string*/
        /*so, return the current char directly*/
        if ( '*' != cur_char )
        {
            next_char = cur_char;
            *ch = '/';
            return ( 0 );
        }

        /*else the char is '*', then enter a comment string*/
        cur_char = fgetc(file);
        while ( EOF != cur_char )
        {
            if ( '*' == cur_char )
            {
                cur_char = fgetc(file);
                if ( EOF == cur_char )
                {
                    sys_log(LOGSTDOUT,
                            "dbg_get_one_char_from_file: find a incompleted comment string.\n");
                    exit( 0 );
                }

                if ('/' == cur_char )
                {
                    return dbg_get_one_char_from_file(file, ch);
                }
            }
            else
            {
                cur_char = fgetc(file);
            }
        }
    }

    /*if the char is NOT '/' then it */
    if ( 0xFF == cur_char || EOF == cur_char)
    {
        return ( DBG_EOF );
    }

    *ch = (UINT8)cur_char;

    return ( 0 );
}


/**
*
*   read a string from the file.
*   comment will be skipped and any space char will terminate the string
*
**/
UINT32 dbg_get_one_str_from_file(FILE *log, UINT8 *desstr, UINT32 maxlen,UINT32 *retlen)
{
    UINT32 index;
    UINT8 ch;
    UINT32 ret;

    /*skip the first spaces*/
    ret = 0;
    do
    {
        ret = dbg_get_one_char_from_file(log, &ch);
    }while( 0 == ret && EOF != (char)ch && EC_TRUE == DBG_ISSPACE(ch) );

    if ( DBG_EOF == ret)
    {
        return (DBG_EOF);
    }

    ret = 0;
    index = 0;
    while( 0 == ret && EOF != (char)ch && EC_FALSE == DBG_ISSPACE(ch) && index < maxlen)
    {
        desstr[ index ] = ch;
        index ++;

        ret = dbg_get_one_char_from_file(log, &ch);
    }
    if ( DBG_EOF == ret)
    {
        return (DBG_EOF);
    }

    if ( index >= maxlen )
    {
        dbg_log(SEC_0047_DEBUG, 0)(LOGSTDOUT,"error:dbg_get_one_str_from_file: buffer is not enough (index = %ld).\n",
                index);
        return ((UINT32)( -1 ));
    }

    if ( index < maxlen)
    {
        desstr[ index ] = '\0';
    }

    /*okay, the return length does not include the EOL(End Of Line) char*/
    *retlen = index;

    return 0;
}

/**
*
* init UINT32
*
**/
UINT32 dbg_init_uint32_ptr(UINT32 *num)
{
    (*num) = 0;
    return (0);
}

/**
*
* init UINT32
*
**/
UINT32 dbg_clean_uint32_ptr(UINT32 *num)
{
    (*num) = 0;
    return (0);
}

/**
*
* free UINT32
*
**/
UINT32 dbg_free_uint32_ptr(UINT32 *num)
{
    (*num) = 0;
    return (0);
}

/**
*
* init uint64_t
*
**/
uint64_t dbg_init_uint64_ptr(uint64_t *num)
{
    (*num) = 0;
    return (0);
}

/**
*
* init uint64_t
*
**/
uint64_t dbg_clean_uint64_ptr(uint64_t *num)
{
    (*num) = 0;
    return (0);
}

/**
*
* free uint64_t
*
**/
uint64_t dbg_free_uint64_ptr(uint64_t *num)
{
    (*num) = 0;
    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
