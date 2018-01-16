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

#include "type.h"
#include "clistbase.h"

#include "mm.h"
#include "log.h"


/*for safe reason, when data handler is not given, set to default null function*/
static EC_BOOL clistbase_null_default(void *data)
{
    return (EC_TRUE);
}

static EC_BOOL clistbase_cmp_default(const void *data_1, const void *data_2)
{
    if(data_1 == data_2)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

static EC_BOOL clistbase_walker_default(const void *data_1, const void *data_2)
{
    if(data_1 <= data_2)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void clistbase_init(CLISTBASE *clistbase)
{
    CLISTBASE_HEAD_INIT(clistbase);

    clistbase->size = 0;

    return;
}

EC_BOOL clistbase_is_empty(const CLISTBASE *clistbase)
{
    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

CLISTBASE_NODE * clistbase_push_back(CLISTBASE *clistbase, const void *data)
{
    CLISTBASE_NODE *clistbase_node;

    clistbase_node = (CLISTBASE_NODE *)data;

    CLISTBASE_NODE_ADD_BACK(clistbase, clistbase_node);

    clistbase->size ++;

    return clistbase_node;
}

CLISTBASE_NODE * clistbase_push_front(CLISTBASE *clistbase, const void *data)
{
    CLISTBASE_NODE *clistbase_node;

    clistbase_node = (CLISTBASE_NODE *)data;

    CLISTBASE_NODE_ADD_FRONT(clistbase, clistbase_node);

    clistbase->size ++;

    return clistbase_node;
}

void *clistbase_pop_back(CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    if(EC_TRUE == clistbase_is_empty(clistbase))
    {
        return (void *)0;
    }

    clistbase_node = CLISTBASE_LAST_NODE(clistbase);
    CLISTBASE_NODE_DEL(clistbase_node);

    data = CLISTBASE_NODE_DATA(clistbase_node);

    clistbase->size --;

    return (data);
}

void *clistbase_pop_front(CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    if(EC_TRUE == clistbase_is_empty(clistbase))
    {
        return (void *)0;
    }

    clistbase_node = CLISTBASE_FIRST_NODE(clistbase);
    CLISTBASE_NODE_DEL(clistbase_node);

    data = CLISTBASE_NODE_DATA(clistbase_node);

    clistbase->size --;

    return data;
}

void *clistbase_back(const CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    clistbase_node = CLISTBASE_LAST_NODE(clistbase);
    if(clistbase_node == CLISTBASE_NULL_NODE(clistbase))
    {
        return (void *)0;
    }

    data = CLISTBASE_NODE_DATA(clistbase_node);

    return data;
}

void *clistbase_front(const CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    clistbase_node = CLISTBASE_FIRST_NODE(clistbase);
    if(clistbase_node == CLISTBASE_NULL_NODE(clistbase))
    {
        return (void *)0;
    }    
   
    data = CLISTBASE_NODE_DATA(clistbase_node);

    return data;
}

CLISTBASE_NODE *clistbase_first(const CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node_first;

    clistbase_node_first = CLISTBASE_FIRST_NODE(clistbase);
    if(clistbase_node_first == CLISTBASE_NULL_NODE(clistbase))
    {
        return (CLISTBASE_NODE *)0;
    }

    return clistbase_node_first;
}

CLISTBASE_NODE *clistbase_last(const CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node_last;

    clistbase_node_last = CLISTBASE_LAST_NODE(clistbase);
    if(clistbase_node_last == CLISTBASE_NULL_NODE(clistbase))
    {
        return (CLISTBASE_NODE *)0;
    }

    return clistbase_node_last;
}

CLISTBASE_NODE *clistbase_next(const CLISTBASE *clistbase, const CLISTBASE_NODE *clistbase_node)
{
    CLISTBASE_NODE *clistbase_node_next;

    if(0 == clistbase_node)
    {
        return (CLISTBASE_NODE *)0;
    }

    clistbase_node_next = CLISTBASE_NODE_NEXT(clistbase_node);
    if(clistbase_node_next == CLISTBASE_NULL_NODE(clistbase))
    {
        return (CLISTBASE_NODE *)0;
    }

    return clistbase_node_next;
}

CLISTBASE_NODE *clistbase_prev(const CLISTBASE *clistbase, const CLISTBASE_NODE *clistbase_node)
{
    CLISTBASE_NODE *clistbase_node_prev;

    if(0 == clistbase_node)
    {
        return (CLISTBASE_NODE *)0;
    }

    clistbase_node_prev = CLISTBASE_NODE_PREV(clistbase_node);
    if(clistbase_node_prev == CLISTBASE_NULL_NODE(clistbase))
    {
        return (CLISTBASE_NODE *)0;
    }

    return clistbase_node_prev;
}

void *clistbase_first_data(const CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node_first;

    clistbase_node_first = CLISTBASE_FIRST_NODE(clistbase);
    if(clistbase_node_first == CLISTBASE_NULL_NODE(clistbase))
    {
        return (void *)0;
    }

    return (void *)CLISTBASE_NODE_DATA(clistbase_node_first);
}

void *clistbase_last_data(const CLISTBASE *clistbase)
{
    CLISTBASE_NODE *clistbase_node_last;

    clistbase_node_last = CLISTBASE_LAST_NODE(clistbase);
    if(clistbase_node_last == CLISTBASE_NULL_NODE(clistbase))
    {
        return (void *)0;
    }

    return (void *)CLISTBASE_NODE_DATA(clistbase_node_last);
}

UINT32 clistbase_size(const CLISTBASE *clistbase)
{
    return clistbase->size;
}

void clistbase_loop_front(const CLISTBASE *clistbase, EC_BOOL (*handler)(void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);
        (handler)( data );
    }
    return;
}

void clistbase_loop_back(const CLISTBASE *clistbase, EC_BOOL (*handler)(void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    CLISTBASE_LOOP_PREV(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);
        (handler)( data );
    }
    return;
}

void clistbase_print(LOG *log, const CLISTBASE *clistbase, void (*print)(LOG *, const void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    UINT32 pos;

    sys_log(log, "size = %ld\n", clistbase->size);

    pos = 0;
    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);

        sys_log(log, "No. %ld: [%p] ", pos ++, clistbase_node);

        if(0 != print)
        {
            (print)( log, data );
        }
        else
        {
            sys_print(log, " %lx\n", data);
        }
    }
    return;
}

void clistbase_print_level(LOG *log, const CLISTBASE *clistbase, const UINT32 level, void (*print)(LOG *, const void *, const UINT32))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    UINT32 pos;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        sys_log(log, "(null)\n");

        return;
    }

    pos = 0;
    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);
        if(0 != print)
        {
            (print)( log, data, level );
        }
        else
        {
            sys_log(log, "No. %ld: ", pos ++);
            sys_print(log, " %lx\n", data);
        }
    }
    return;
}

void clistbase_print_plain(LOG *log, const CLISTBASE *clistbase, void (*print)(LOG *, const void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    UINT32 pos;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return;
    }

    pos = 0;
    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);

        if(0 != print)
        {
            (print)( log, data );
        }
    }
    return;
}

void clistbase_print_plain_level(LOG *log, const CLISTBASE *clistbase, const UINT32 level, void (*print)(LOG *, const void *, const UINT32))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    UINT32 pos;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return;
    }

    pos = 0;
    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);
        if(0 != print)
        {
            (print)( log, data, level );
        }
    }
    return;
}

void clistbase_sprint(CSTRING *cstring, const CLISTBASE *clistbase, void (*sprint)(CSTRING *, const void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    UINT32 pos;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        cstring_format(cstring, "(null)\n");

        return;
    }
    pos = 0;
    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        data = CLISTBASE_NODE_DATA(clistbase_node);

        cstring_format(cstring, "No. %ld: ", pos ++);

        if(0 != sprint)
        {
            (sprint)( cstring, data );
        }
        else
        {
            cstring_format(cstring, " %lx\n", data);
        }
    }
    return;
}

CLISTBASE_NODE * clistbase_search_front(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    CLISTBASE_NODE *clistbase_node;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return (NULL_PTR);
    }

    if(NULL_PTR == cmp)
    {
        cmp = clistbase_cmp_default;
    }

    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        if(EC_TRUE == cmp(CLISTBASE_NODE_DATA(clistbase_node), data))
        {
            return clistbase_node;
        }
    }
    return (NULL_PTR);
}

CLISTBASE_NODE * clistbase_search_back(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    CLISTBASE_NODE *clistbase_node;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return (NULL_PTR);
    }

    if(NULL_PTR == cmp)
    {
        cmp = clistbase_cmp_default;
    }

    CLISTBASE_LOOP_PREV(clistbase, clistbase_node)
    {
        if(EC_TRUE == cmp(CLISTBASE_NODE_DATA(clistbase_node), data))
        {
            return clistbase_node;
        }
    }
    return (NULL_PTR);
}

void * clistbase_search_data_front(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    CLISTBASE_NODE *clistbase_node;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return (NULL_PTR);
    }

    if(NULL_PTR == cmp)
    {
        cmp = clistbase_cmp_default;
    }

    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        if(EC_TRUE == cmp(CLISTBASE_NODE_DATA(clistbase_node), data))
        {
            return CLISTBASE_NODE_DATA(clistbase_node);
        }
    }
    return (NULL_PTR);
}

void * clistbase_search_data_back(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    CLISTBASE_NODE *clistbase_node;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return (NULL_PTR);
    }

    if(NULL_PTR == cmp)
    {
        cmp = clistbase_cmp_default;
    }

    CLISTBASE_LOOP_PREV(clistbase, clistbase_node)
    {
        if(EC_TRUE == cmp(CLISTBASE_NODE_DATA(clistbase_node), data))
        {
            return CLISTBASE_NODE_DATA(clistbase_node);
        }
    }
    return (NULL_PTR);
}

void *clistbase_rmv(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node)
{
    void *data;

    data = CLISTBASE_NODE_DATA(clistbase_node);
    CLISTBASE_NODE_DEL(clistbase_node);

    clistbase->size --;

    return (data);
}

void *clistbase_del(CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *cur_data;

    if(EC_TRUE == CLISTBASE_IS_EMPTY(clistbase))
    {
        return (NULL_PTR);
    }

    if(NULL_PTR == cmp)
    {
        cmp = clistbase_cmp_default;
    }

    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        if(EC_TRUE == cmp(CLISTBASE_NODE_DATA(clistbase_node), data))
        {
            cur_data = CLISTBASE_NODE_DATA(clistbase_node);
            CLISTBASE_NODE_DEL(clistbase_node);
 
            clistbase->size --;

            return (cur_data);
        }
    }
    return (NULL_PTR);
}

void *clistbase_erase(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node)
{
    void *data;

    if(NULL_PTR == clistbase_node)
    {
        return (NULL_PTR);
    }

    CLISTBASE_NODE_DEL(clistbase_node);
    data = CLISTBASE_NODE_DATA(clistbase_node);

    /*WARNING: if clistbase_node does not belong to this clistbase, clistbase->size will be changed exceptionally*/
    /*the solution maybe discard size field and count size by run-through the clist*/
    clistbase->size --;

    return data;
}

/*move from current position to tail*/
EC_BOOL clistbase_move_back(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node)
{
    CLISTBASE_NODE_DEL(clistbase_node);
    CLISTBASE_NODE_ADD_BACK(clistbase, clistbase_node);
    return (EC_TRUE);
}

/*move from current position to head*/
EC_BOOL clistbase_move_front(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node)
{
    CLISTBASE_NODE_DEL(clistbase_node);
    CLISTBASE_NODE_ADD_FRONT(clistbase, clistbase_node);
    return (EC_TRUE);
}

void clistbase_clean(CLISTBASE *clistbase, EC_BOOL (*cleaner)(void *))
{
    CLISTBASE_NODE *clistbase_node;
    void *data;

    /*accept null cleaner*/
    if(0 == cleaner)
    {
        cleaner = clistbase_null_default;
    }

    while( EC_FALSE == CLISTBASE_IS_EMPTY(clistbase) )
    {
        clistbase_node = CLISTBASE_LAST_NODE(clistbase);
        CLISTBASE_NODE_DEL(clistbase_node);

        clistbase->size --;

        data = CLISTBASE_NODE_DATA(clistbase_node);
        
        cleaner(data);
    }

    clistbase->size = 0;

    return;
}

void clistbase_handover(CLISTBASE *clistbase_src, CLISTBASE *clistbase_des)
{
    while( EC_FALSE == CLISTBASE_IS_EMPTY(clistbase_src) )
    {
        CLISTBASE_NODE *clistbase_node;
     
        clistbase_node = CLISTBASE_FIRST_NODE(clistbase_src);
        CLISTBASE_NODE_DEL(clistbase_node);

        CLISTBASE_NODE_ADD_BACK(clistbase_des, clistbase_node);
    } 

    clistbase_des->size = clistbase_src->size;
    clistbase_src->size = 0;
    return;
}

EC_BOOL clistbase_walk(const CLISTBASE *clistbase, void *data, EC_BOOL (*walker)(const void *, void *))
{
    CLISTBASE_NODE *clistbase_node;

    CLISTBASE_LOOP_NEXT(clistbase, clistbase_node)
    {
        if(EC_FALSE == walker(CLISTBASE_NODE_DATA(clistbase_node), data))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/
