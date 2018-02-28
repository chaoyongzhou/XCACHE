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

/******************************************************************************
*
*  source code is modified from github:
*     https://github.com/VladimirTyrin/RingBuffer
*  
*  thanks the author Vladimir Tyrin.
*
*******************************************************************************/

#include "type.h"
#include "log.h"
#include "mm.h"

#include "crbuff.h"

CRBUFF *crbuff_new()
{
    CRBUFF *crbuff;

    crbuff = (CRBUFF *) safe_malloc(sizeof(CRBUFF), LOC_CRBUFF_0001);
    if(NULL_PTR == crbuff)
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_new: "
                                               "no memory\n");    
        return (NULL_PTR);
    }

    crbuff_init(crbuff);

    return (crbuff);
}

EC_BOOL crbuff_init(CRBUFF *crbuff)
{
    if(NULL_PTR != crbuff)
    {
        CRBUFF_CAPACITY(crbuff) = 0;
        CRBUFF_DATA(crbuff)     = NULL_PTR;
        CRBUFF_BEG(crbuff)      = NULL_PTR;
        CRBUFF_END(crbuff)      = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL crbuff_clean(CRBUFF *crbuff)
{
    if(NULL_PTR != crbuff)
    {
        if(NULL_PTR != CRBUFF_DATA(crbuff))
        {
            safe_free(CRBUFF_DATA(crbuff), LOC_CRBUFF_0001);
            CRBUFF_DATA(crbuff) = NULL_PTR;
        }
        
        CRBUFF_BEG(crbuff) = NULL_PTR;
        CRBUFF_END(crbuff) = NULL_PTR; 

        CRBUFF_CAPACITY(crbuff) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL crbuff_free(CRBUFF *crbuff)
{
    if(NULL_PTR != crbuff)
    {
        crbuff_clean(crbuff);
        safe_free(crbuff, LOC_CRBUFF_0001);  
    }
    return (EC_TRUE);
}

EC_BOOL crbuff_reset(CRBUFF *crbuff)
{
    if(NULL_PTR != crbuff)
    {
        CRBUFF_BEG(crbuff) = CRBUFF_DATA(crbuff);
        CRBUFF_END(crbuff) = CRBUFF_DATA(crbuff);    
    }

    return (EC_TRUE);
}

EC_BOOL crbuff_set_capacity(CRBUFF *crbuff, const UINT32 capacity)
{
    void    *data;

    /**
     * note:
     *
     * https://en.wikipedia.org/wiki/Circular_crbuff#Always_keep_one_slot_open
     * policy is used
     *
    **/
    data = safe_malloc(capacity + 1, LOC_CRBUFF_0001);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_set_capacity:"
                                               "alloc %ld bytes failed\n",
                                               capacity);
        return (EC_FALSE);
    }  

    CRBUFF_CAPACITY(crbuff) = capacity;

    CRBUFF_DATA(crbuff) = data;
    
    /* end == begin, so crbuff is empty */
    CRBUFF_BEG(crbuff)  = data;
    CRBUFF_END(crbuff)  = data;    

    return (EC_TRUE);
}

/*used space size*/
UINT32 crbuff_data_size(const CRBUFF *crbuff)
{
    if(CRBUFF_END(crbuff) >= CRBUFF_BEG(crbuff))
    {
        return (CRBUFF_END(crbuff) - CRBUFF_BEG(crbuff));
    }  

    return (CRBUFF_END(crbuff) + CRBUFF_CAPACITY(crbuff) + 1 - CRBUFF_BEG(crbuff));
}

/*left (not used) space size*/
UINT32 crbuff_room_size(const CRBUFF *crbuff)
{
  return (CRBUFF_CAPACITY(crbuff) - crbuff_data_size(crbuff));
}

EC_BOOL crbuff_push(CRBUFF *crbuff, void *data, const UINT32 data_size)
{
    UINT32  room_size;

    room_size = crbuff_room_size(crbuff);
    if(data_size > room_size)
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_push: "
                                               "room_size %ld < data_size %ld\n",
                                               room_size, data_size);
        return (EC_FALSE);
    }  

    if(CRBUFF_END(crbuff) >= CRBUFF_BEG(crbuff))
    {
        UINT32 end_free_segment;
        
        end_free_segment = CRBUFF_DATA(crbuff) 
                         + CRBUFF_CAPACITY(crbuff) 
                         - CRBUFF_END(crbuff)
                         + (CRBUFF_BEG(crbuff) == CRBUFF_DATA(crbuff) ? 0 : 1);
                         
        if(end_free_segment >= data_size) /* Simple case */
        {
            BCOPY(data, CRBUFF_END(crbuff), data_size);
            
            CRBUFF_END(crbuff) += data_size;
        }
        else
        {
            BCOPY(data                   , CRBUFF_END(crbuff),  end_free_segment            );
            BCOPY(data + end_free_segment, CRBUFF_DATA(crbuff), data_size - end_free_segment);
            
            CRBUFF_END(crbuff) = CRBUFF_DATA(crbuff) + data_size - end_free_segment;
        }

        return (EC_TRUE);
    }

    BCOPY(data, CRBUFF_END(crbuff), data_size);
    CRBUFF_END(crbuff) += data_size;
    return (EC_TRUE);
}

EC_BOOL crbuff_read(CRBUFF *crbuff, void *data, const UINT32 data_size)
{
    UINT32  used_size;
    UINT32  end_data_segment;

    used_size = crbuff_data_size(crbuff);
    if(data_size > used_size)
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_read: "
                                               "used_size %ld < data_size %ld\n",
                                               used_size, data_size);
        return (EC_FALSE);
    }

    if(CRBUFF_END(crbuff) >= CRBUFF_BEG(crbuff))
    {
        BCOPY(CRBUFF_BEG(crbuff), data, data_size);
        return (EC_TRUE);
    }
    
    end_data_segment = CRBUFF_DATA(crbuff) 
                     + CRBUFF_CAPACITY(crbuff) 
                     - CRBUFF_BEG(crbuff)
                     + (CRBUFF_BEG(crbuff) == CRBUFF_DATA(crbuff) ? 0 : 1);
                     
    if(end_data_segment >= data_size) /* Simple case */
    {
        BCOPY(CRBUFF_BEG(crbuff), data, data_size);
    }
    else
    {
        BCOPY(CRBUFF_BEG(crbuff) , data                   , end_data_segment            );
        BCOPY(CRBUFF_DATA(crbuff), data + end_data_segment, data_size - end_data_segment);
    }
    return (EC_TRUE);
}

EC_BOOL crbuff_pop(CRBUFF *crbuff, void *data, const UINT32 data_size)
{
    if(EC_FALSE == crbuff_read(crbuff, data, data_size))
    {
        dbg_log(SEC_0033_CRBUFF, 0)(LOGSTDOUT, "error:crbuff_pop: "
                                               "read %ld bytes failed\n",
                                               data_size);      
        return (EC_FALSE);
    }
    
    CRBUFF_BEG(crbuff) += data_size;
    if(CRBUFF_BEG(crbuff) > CRBUFF_DATA(crbuff) + CRBUFF_CAPACITY(crbuff))
    {
        CRBUFF_BEG(crbuff) -= CRBUFF_CAPACITY(crbuff);
    }
    return (EC_TRUE);
}

void crbuff_print(LOG *log, const CRBUFF *crbuff)
{
    sys_log(log, "[DEBUG] crbuff_print: crbuff %p: "
                 "capacity %ld, beg %ld, end %ld, data size %ld, room size %ld\n",
                 crbuff,
                 CRBUFF_CAPACITY(crbuff),
                 CRBUFF_BEG(crbuff) - CRBUFF_DATA(crbuff),
                 CRBUFF_END(crbuff) - CRBUFF_DATA(crbuff),
                 crbuff_data_size(crbuff),
                 crbuff_room_size(crbuff));

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

