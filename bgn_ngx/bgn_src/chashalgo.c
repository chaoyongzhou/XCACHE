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
#include "log.h"

#include "cmd5.h"
#include "chashalgo.h"
#include "chashalgo.inc"

/* A Simple Hash Function */
UINT32 simple_hash(const UINT32 len, const UINT8 *str)
{
    UINT32 hash;
    UINT32 pos;

    for(hash = 0, pos = 0; pos < len ; pos ++)
    {
        hash = 31 * hash + str[ pos ];
    }

    return (hash & 0x7FFFFFFF);
}

/* RS Hash Function */
UINT32 RS_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 b = 378551;
     UINT32 a = 63689;
     UINT32 hash = 0;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
             hash = hash * a + str[ pos ];
             a *= b;
     }

     return (hash & 0x7FFFFFFF);
}

/* JS Hash Function */
UINT32 JS_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 hash = 1315423911;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
             hash ^= ((hash << 5) + str[ pos ] + (hash >> 2));
     }

     return (hash & 0x7FFFFFFF);
}

/* P. J. Weinberger Hash Function */
UINT32 PJW_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 BitsInUnignedInt = (UINT32)(sizeof(UINT32) * 8);
     UINT32 ThreeQuarters    = (UINT32)((BitsInUnignedInt   * 3) / 4);
     UINT32 OneEighth        = (UINT32)(BitsInUnignedInt / 8);

     UINT32 HighBits         = (UINT32)(0xFFFFFFFF) << (BitsInUnignedInt - OneEighth);
     UINT32 hash             = 0;
     UINT32 test             = 0;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
         hash = (hash << OneEighth) + str[ pos ];
         if ((test = hash & HighBits) != 0)
         {
                 hash = ((hash ^ (test >> ThreeQuarters)) & (~HighBits));
         }
     }

         return (hash & 0x7FFFFFFF);
}

/* ELF Hash Function */
UINT32 ELF_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 hash = 0;
     UINT32 x    = 0;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
         hash = (hash << 4) + str[ pos ];
         if ((x = hash & 0xF0000000L) != 0)
         {
             hash ^= (x >> 24);
             hash &= ~x;
         }
     }

     return (hash & 0x7FFFFFFF);
}

/* BKDR Hash Function */
UINT32 BKDR_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 seed = 131; // 31 131 1313 13131 131313 etc..
     UINT32 hash = 0;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
             hash = hash * seed + str[ pos ];
     }

     return (hash & 0x7FFFFFFF);
}

/* SDBM Hash Function */
UINT32 SDBM_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 hash = 0;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
             hash = (hash << 6) + (hash << 16) + str[ pos ] - hash;
     }

     return (hash & 0x7FFFFFFF);
}

/* DJB Hash Function */
UINT32 DJB_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 hash = 5381;
     UINT32 pos;

     for(pos = 0; pos < len; pos ++)
     {
         hash += (hash << 5) + str[ pos ];
     }

     return (hash & 0x7FFFFFFF);
}

/* AP Hash Function */
UINT32 AP_hash(const UINT32 len, const UINT8 *str)
{
     UINT32 hash = 0;
     UINT32 pos;
     for(pos = 0; pos < len; pos ++)
     {
         if (0 == (pos & 1))
         {
             hash ^= ((hash << 7) ^ ((UINT32)str[ pos ]) ^ (hash >> 3));
         }
         else
         {
             hash ^= (~((hash << 11) ^ ((UINT32)str[ pos ]) ^ (hash >> 5)));
         }
     }

     return (hash & 0x7FFFFFFF);
}

/* CRC Hash Function */
UINT32 CRC_hash(const UINT32 len, const UINT8 *str)
{
    UINT32  sum     = 0;
    UINT16 *w       = (UINT16 *)str;
    UINT16  answer  = 0;
    UINT32  pos;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    for(sum = 0, pos = len; pos > 1; pos -= 2)
    {
        sum += (*w++);
    }
    /*
     * mop up an odd byte, if necessary
     */
    if ( 1 == pos )
    {
        *( UINT8 * )( &answer ) = *( UINT8 * )w ;
        sum += answer;
    }
    /*
     * add back carry outs from top 16 bits to low 16 bits
     * add hi 16 to low 16
     */
    sum = ( sum >> 16 ) + ( sum & 0xFFFF );
    /* add carry */
    sum += ( sum >> 16 );
    /* truncate to 16 bits */
    answer = ~sum;

    return (answer & 0xFFFFFFFF);
}

UINT32 MD5_hash(const UINT32 len, const UINT8 *str)
{
    uint32_t  hash;
    uint8_t   digest[ CMD5_DIGEST_LEN ];
    uint8_t   i;

    cmd5_sum(len, str, digest);

    hash = 0;
    for(i = 0; i < 4; i++)
    {
        hash += ((uint32_t)(digest[i * 4 + 3] & 0xFF) << 24)
              | ((uint32_t)(digest[i * 4 + 2] & 0xFF) << 16)
              | ((uint32_t)(digest[i * 4 + 1] & 0xFF) <<  8)
              | ((uint32_t)(digest[i * 4 + 0] & 0xFF));
    }

    return (hash);
}

CHASH_ALGO chash_algo_fetch(const UINT32 chash_algo_id)
{
    CHASH_ALGO_NODE *chash_algo_node;
    UINT32 chash_algo_node_pos;

    if(chash_algo_id < g_chash_algo_nodes_num)
    {
        chash_algo_node = (CHASH_ALGO_NODE *)&(g_chash_algo_nodes[ chash_algo_id ]);
        if(chash_algo_id == CHASH_ALGO_NODE_ID(chash_algo_node))
        {
            return CHASH_ALGO_NODE_FUNC(chash_algo_node);
        }

        for(chash_algo_node_pos = 0; chash_algo_node_pos < g_chash_algo_nodes_num; chash_algo_node_pos ++)
        {
            chash_algo_node = (CHASH_ALGO_NODE *)&(g_chash_algo_nodes[ chash_algo_node_pos ]);
            if(chash_algo_id == CHASH_ALGO_NODE_ID(chash_algo_node))
            {
                return CHASH_ALGO_NODE_FUNC(chash_algo_node);
            }
        }
    }

    dbg_log(SEC_0064_CHASHALGO, 0)(LOGSTDOUT, "error:chash_algo_get: invalid chash_algo_id %ld\n", chash_algo_id);
    return (NULL_PTR);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
