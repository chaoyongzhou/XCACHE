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

#ifndef _CBTREE_H
#define _CBTREE_H

#include "type.h"
#include "mm.h"
#include "log.h"

#define CBTREE_MAX_ORDER                 ((uint8_t) 16)
//#define CBTREE_MAX_ORDER                 ((uint8_t)  5)
#define CBTREE_MAX_VERSION               ((uint8_t)  3)

#define CBTREE_IS_GENERAL_STRING_TYPE    ((uint8_t)  1)
#define CBTREE_IS_BGT_ROOT_TABLE_TYPE    ((uint8_t)  2)
#define CBTREE_IS_BGT_META_TABLE_TYPE    ((uint8_t)  3)
#define CBTREE_IS_BGT_COLF_TABLE_TYPE    ((uint8_t)  4)
#define CBTREE_IS_BGT_USER_TABLE_TYPE    ((uint8_t)  5)
#define CBTREE_IS_ERR_TYPE               ((uint8_t) -1)

#define CBTREE_ERR_OFFSET                ((uint32_t)-1)
#define CBTREE_HDR_OFFSET                ((uint32_t)64)
#define CBTREE_KEY_MIN_SIZE              ((uint32_t) 8)/*one word size to store a pointer*/
#define CBTREE_NODE_MIN_SIZE             ((uint32_t) 8)/*one word size to store a pointer*/

#define CBTREE_DIRTY_FLAG                ((uint8_t)  1)
#define CBTREE_ERR_FLAG                  ((uint8_t)  0)

typedef struct _CBTREE           CBTREE;            /* A B+Tree.          */
typedef struct _CBTREE_NODE      CBTREE_NODE;      /* A node in a B+Tree.*/
typedef struct _CBTREE_KEY       CBTREE_KEY;       /* key in a B+Tree.   */

struct _CBTREE_KEY
{
    union
    {
        struct
        {
            uint32_t offset;/* Current file/buff pos when flush         */
            uint32_t rsvd;
        }e;/*used for encoding and record the offset info*/
        
        CBTREE_KEY *ptr;/*used for decoding override with memory addr where this key was stored at*/
        
    }u;
    uint8_t *kv[CBTREE_MAX_VERSION];
};
#define CBTREE_KEY_OFFSET(cbtree_key)   ((cbtree_key)->u.e.offset)
#define CBTREE_KEY_PTR(cbtree_key)      ((cbtree_key)->u.ptr)
#define CBTREE_KEY_KV(cbtree_key, ver)  ((cbtree_key)->kv[ ver ])
#define CBTREE_KEY_LATEST(cbtree_key)   (CBTREE_KEY_KV(cbtree_key, 0))

typedef uint8_t * (* CBTREE_KEY_DUP_LATEST)(const uint8_t *, const word_t);
typedef void      (* CBTREE_KEY_FREE)(uint8_t *, const word_t);
typedef uint32_t  (* CBTREE_KEY_TLEN)(const uint8_t *);
typedef int       (* CBTREE_KEY_CMP)(const uint8_t *, const uint8_t *);
typedef void      (* CBTREE_KEY_PRINT)(LOG *, const uint8_t *);
typedef EC_BOOL   (* CBTREE_KEY_ENCODE_SIZE)(const uint8_t *, uint32_t *);
typedef EC_BOOL   (* CBTREE_KEY_ENCODE)(const uint8_t *, uint8_t *, const uint32_t , uint32_t *);
typedef EC_BOOL   (* CBTREE_KEY_DECODE)(uint8_t **, uint8_t *, const uint32_t, uint32_t *);

typedef void (*CBTREE_KEY_PRINTER)(LOG *, const CBTREE *, const CBTREE_KEY *);

typedef struct
{
    CBTREE_KEY_DUP_LATEST  key_dup_op;
    CBTREE_KEY_FREE        key_free_op;
    CBTREE_KEY_TLEN        key_tlen_op;
    CBTREE_KEY_CMP         key_cmp_op;
    CBTREE_KEY_PRINT       key_print_op;
    CBTREE_KEY_ENCODE_SIZE key_encode_size_op;
    CBTREE_KEY_ENCODE      key_encode_op;    
    CBTREE_KEY_DECODE      key_decode_op;
}CBTREE_KEY_OPERATOR;

#define CBTREE_KEY_OPERATOR_DUP(cbtree_key_op)              ((cbtree_key_op)->key_dup_op)
#define CBTREE_KEY_OPERATOR_FREE(cbtree_key_op)             ((cbtree_key_op)->key_free_op)
#define CBTREE_KEY_OPERATOR_TLEN(cbtree_key_op)             ((cbtree_key_op)->key_tlen_op)
#define CBTREE_KEY_OPERATOR_CMP(cbtree_key_op)              ((cbtree_key_op)->key_cmp_op)
#define CBTREE_KEY_OPERATOR_PRINT(cbtree_key_op)            ((cbtree_key_op)->key_print_op)
#define CBTREE_KEY_OPERATOR_ENCODE_SIZE(cbtree_key_op)      ((cbtree_key_op)->key_encode_size_op)
#define CBTREE_KEY_OPERATOR_ENCODE(cbtree_key_op)           ((cbtree_key_op)->key_encode_op)
#define CBTREE_KEY_OPERATOR_DECODE(cbtree_key_op)           ((cbtree_key_op)->key_decode_op)


/*note: 2 * min_leaf = order or order - 1       */
/*note: 2 * min_internal = order - 1 or order - 2*/
struct _CBTREE
{
    uint32_t     size;         /* The size of the tree.                    */
    uint8_t      order;        /* The order of this tree.                  */  
    uint8_t      max_ver;      /* Max versions per kv                      */
    uint8_t      key_type;     /* B+Tree key type such as string,num,kv,etc*/
    uint8_t      min_leaf;     /* Minimum kv count in a leaf               */
    
    uint8_t      min_internal; /* Minimum kv count in an internal node.    */    
    uint8_t      height;       /* The height of the tree                   */    
    uint8_t      dirty;        /* dirty flag                               */    
    uint16_t     rsvd1;
    uint32_t     tlen;         /* total len of all keys,include multi vers */

    CBTREE_NODE *root_node;    /* The root node                            */
    CBTREE_NODE *left_leaf;    /* The left-most leaf                       */

    /*key operation*/
    CBTREE_KEY_OPERATOR          key_op;
    
};

#define CBTREE_SIZE(cbtree)                  ((cbtree)->size)
#define CBTREE_ORDER(cbtree)                 ((cbtree)->order)
#define CBTREE_MAX_VER(cbtree)               ((cbtree)->max_ver)
#define CBTREE_KEY_TYPE(cbtree)              ((cbtree)->key_type)
#define CBTREE_MIN_LEAF(cbtree)              ((cbtree)->min_leaf)
#define CBTREE_MIN_INTR(cbtree)              ((cbtree)->min_internal)
#define CBTREE_HEIGHT(cbtree)                ((cbtree)->height)
#define CBTREE_DIRTY(cbtree)                 ((cbtree)->dirty)
#define CBTREE_ROOT_NODE(cbtree)             ((cbtree)->root_node)
#define CBTREE_LEFT_LEAF(cbtree)             ((cbtree)->left_leaf)
#define CBTREE_TLEN(cbtree)                  ((cbtree)->tlen)

#define CBTREE_KEY_OP(cbtree)                (&((cbtree)->key_op))
#define CBTREE_KEY_DUP_OP(cbtree)            ((cbtree)->key_op.key_dup_op)
#define CBTREE_KEY_FREE_OP(cbtree)           ((cbtree)->key_op.key_free_op)
#define CBTREE_KEY_TLEN_OP(cbtree)           ((cbtree)->key_op.key_tlen_op)
#define CBTREE_KEY_CMP_OP(cbtree)            ((cbtree)->key_op.key_cmp_op)
#define CBTREE_KEY_PRINT_OP(cbtree)          ((cbtree)->key_op.key_print_op)
#define CBTREE_KEY_ENCODE_SIZE_OP(cbtree)    ((cbtree)->key_op.key_encode_size_op)
#define CBTREE_KEY_ENCODE_OP(cbtree)         ((cbtree)->key_op.key_encode_op)
#define CBTREE_KEY_DECODE_OP(cbtree)         ((cbtree)->key_op.key_decode_op)

#define CBTREE_IS_DIRTY(cbtree)              (CBTREE_DIRTY_FLAG & CBTREE_DIRTY(cbtree))
#define CBTREE_SET_DIRTY(cbtree)             (CBTREE_DIRTY(cbtree) |= CBTREE_DIRTY_FLAG)
#define CBTREE_CLR_DIRTY(cbtree)             (CBTREE_DIRTY(cbtree) &= ((uint8_t)~CBTREE_DIRTY_FLAG))

#define CBTREE_NODE_LEAF_FLAG                ((uint8_t) 1)
#define CBTREE_NODE_ERR_FLAG                 ((uint8_t) 0)

struct _CBTREE_NODE
{
    union
    {
        struct
        {
            uint8_t      count;        /* The number of keys in the node.    */
            uint8_t      flag;         /* leaf node or not                   */
            uint16_t     rsvd;
            union
            {
                uint32_t     rsvd2;    
                uint32_t     offset;   /* Current filePos when flush         */
            }u2;
        }e;/*used for encoding and record the offset info*/
        CBTREE_NODE *ptr;/*used for decoding override with memory addr where this node was stored at*/
    }u1;

    CBTREE_KEY  *keys[CBTREE_MAX_ORDER];     /*key part             */
    /*when node is leaf, all children is null pointer, except the last one which point to next leaf node*/
    /*when node is not leaf, children num = count + 1*/
    CBTREE_NODE *children[CBTREE_MAX_ORDER]; /* children node       */    
};

#define CBTREE_NODE_COUNT(cbtree_node)              ((cbtree_node)->u1.e.count)
#define CBTREE_NODE_FLAG(cbtree_node)               ((cbtree_node)->u1.e.flag)
#define CBTREE_NODE_OFFSET(cbtree_node)             ((cbtree_node)->u1.e.u2.offset)
#define CBTREE_NODE_PTR(cbtree_node)                ((cbtree_node)->u1.ptr)
#define CBTREE_NODE_CHILDREN(cbtree_node)           ((cbtree_node)->children)
#define CBTREE_NODE_CHILD(cbtree_node, pos)         ((cbtree_node)->children[ pos ])
#define CBTREE_NODE_KEY(cbtree_node, pos)           ((cbtree_node)->keys[ pos ])
#define CBTREE_NODE_LATEST_KEY(cbtree_node, pos)    (CBTREE_KEY_LATEST(CBTREE_NODE_KEY(cbtree_node, pos)))

#define CBTREE_NODE_IS_LEAF(cbtree_node)      (CBTREE_NODE_LEAF_FLAG == CBTREE_NODE_FLAG(cbtree_node))
#define CBTREE_NODE_SET_LEAF(cbtree_node)     (CBTREE_NODE_FLAG(cbtree_node) = CBTREE_NODE_LEAF_FLAG)
#define CBTREE_NODE_LEAF_STR(cbtree_node)     (CBTREE_NODE_IS_LEAF(cbtree_node)?(const char *)"leaf":(const char *)"not leaf")

EC_BOOL cbtree_key_op_init(CBTREE_KEY_OPERATOR *cbtree_key_op);

EC_BOOL cbtree_key_op_clean(CBTREE_KEY_OPERATOR *cbtree_key_op);


CBTREE_KEY *cbtree_key_new(const CBTREE *cbtree);

CBTREE_KEY *cbtree_key_make(const CBTREE *cbtree, const uint8_t *key);

EC_BOOL cbtree_key_init(const CBTREE *cbtree, CBTREE_KEY *cbtree_key);

EC_BOOL cbtree_key_clean(const CBTREE *cbtree, CBTREE_KEY *cbtree_key);

EC_BOOL cbtree_key_free(const CBTREE *cbtree, CBTREE_KEY *cbtree_key);

EC_BOOL cbtree_key_push(const CBTREE *cbtree, CBTREE_KEY *cbtree_key, const uint8_t *key);

EC_BOOL cbtree_key_update(const CBTREE *cbtree, CBTREE_KEY *cbtree_key_des, CBTREE_KEY *cbtree_key_src);

void cbtree_key_print(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key);

int cbtree_key_cmp(const CBTREE *cbtree, const CBTREE_KEY *cbtree_key_1st, const CBTREE_KEY *cbtree_key_2nd);

EC_BOOL cbtree_key_clone(const CBTREE *cbtree, const CBTREE_KEY *cbtree_key_src, CBTREE_KEY *cbtree_key_des);

uint8_t *cbtree_key_dup_latest(const CBTREE *cbtree, const CBTREE_KEY * cbtree_key);

CBTREE_KEY *cbtree_key_dup_all(const CBTREE *cbtree, const CBTREE_KEY * cbtree_key);

uint32_t cbtree_key_tlen(const CBTREE *cbtree, const CBTREE_KEY * cbtree_key);
   
CBTREE_NODE *cbtree_node_new(const CBTREE *cbtree);

EC_BOOL cbtree_node_init(const CBTREE *cbtree, CBTREE_NODE *cbtree_node);

EC_BOOL cbtree_node_clean(const CBTREE *cbtree, CBTREE_NODE *cbtree_node);

EC_BOOL cbtree_node_free(const CBTREE *cbtree, CBTREE_NODE *cbtree_node);

EC_BOOL cbtree_node_set_key(CBTREE *cbtree, CBTREE_NODE *cbtree_node, const uint8_t pos, const uint8_t *key);

uint8_t *cbtree_node_get_key(const CBTREE *cbtree, CBTREE_NODE *cbtree_node, const uint8_t pos);

uint32_t cbtree_node_count_tlen(const CBTREE *cbtree, const CBTREE_NODE *cbtree_node);

/*get right most leaf*/
CBTREE_NODE *cbtree_node_get_r_leaf(const CBTREE *cbtree, CBTREE_NODE *node);

/*get left most leaf*/
CBTREE_NODE *cbtree_node_get_l_leaf(const CBTREE *cbtree, CBTREE_NODE *node);

/*get right most key*/
CBTREE_KEY  *cbtree_node_get_r_key(const CBTREE *cbtree, CBTREE_NODE *node);

void cbtree_node_print(LOG *log, const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, uint8_t i, CBTREE_KEY_PRINTER key_printer);

CBTREE *cbtree_new(const uint8_t order, const uint8_t max_ver, const uint8_t key_type);

EC_BOOL cbtree_init(CBTREE *cbtree, const uint8_t order, const uint8_t max_ver, const uint8_t key_type);

EC_BOOL cbtree_clean(CBTREE *cbtree);

EC_BOOL cbtree_free(CBTREE *cbtree);

void cbtree_print_itself(LOG *log, const CBTREE *cbtree);

void cbtree_print(LOG *log, const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, uint8_t i, CBTREE_KEY_PRINTER key_printer);

void cbtree_runthrough(LOG *log, const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, CBTREE_KEY_PRINTER key_printer);

EC_BOOL cbtree_checker(const CBTREE *cbtree, CBTREE_KEY_PRINTER key_printer, CBTREE_KEY **min_key, UINT32 *total_key_num);

EC_BOOL cbtree_check_in_depth(const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, CBTREE_KEY_PRINTER key_printer);

EC_BOOL cbtree_is_empty(const CBTREE *cbtree);

EC_BOOL cbtree_insert(CBTREE *cbtree, const uint8_t *key);

EC_BOOL cbtree_delete(CBTREE *cbtree, const uint8_t *key);

CBTREE_KEY *cbtree_search(CBTREE *cbtree, const uint8_t *key);

uint32_t cbtree_count_size(const CBTREE *cbtree);

uint32_t cbtree_count_tlen(const CBTREE *cbtree);

uint8_t cbtree_count_height(const CBTREE *cbtree);

EC_BOOL cbtree_split(CBTREE *cbtree, CBTREE **cbtree_son);

CBTREE * cbtree_merge(CBTREE *cbtree_left, CBTREE *cbtree_right);

EC_BOOL cbtree_key_encode_size(CBTREE *cbtree, CBTREE_KEY *cbtree_key, uint32_t *size);

EC_BOOL cbtree_key_encode(CBTREE *cbtree, CBTREE_KEY *cbtree_key, uint8_t *buff, const uint32_t size, uint32_t *pos);

CBTREE_KEY *cbtree_key_decode(CBTREE *cbtree, uint8_t *buff, const uint32_t size, uint32_t *pos);

EC_BOOL cbtree_node_encode_size(CBTREE *cbtree, CBTREE_NODE *root_node, uint32_t *pos);

EC_BOOL cbtree_node_encode(CBTREE *cbtree, CBTREE_NODE *root_node, uint8_t *buff, const uint32_t size, uint32_t *pos);

CBTREE_NODE *cbtree_node_decode(CBTREE *cbtree, uint8_t *buff, const uint32_t size, uint32_t *pos);

EC_BOOL cbtree_encode_size(CBTREE *cbtree, uint32_t *pos);

EC_BOOL cbtree_encode(CBTREE *cbtree, uint8_t *buff, const uint32_t size, uint32_t *pos);

CBTREE * cbtree_decode(uint8_t *buff, const uint32_t size);

EC_BOOL cbtree_is_equal(const CBTREE *cbtree_1st, const CBTREE *cbtree_2nd);

EC_BOOL cbtree_is_dirty(const CBTREE *cbtree);

EC_BOOL cbtree_set_dirty(CBTREE *cbtree);

EC_BOOL cbtree_clear_dirty(CBTREE *cbtree);

EC_BOOL cbtree_flush_posix(CBTREE *cbtree, int fd);
EC_BOOL cbtree_flush_hsdfs(CBTREE *cbtree, const CSTRING *fname_cstr, const UINT32 cdfs_md_id);
EC_BOOL cbtree_flush(CBTREE *cbtree, const char *fname);

CBTREE * cbtree_load_posix(int fd);
CBTREE * cbtree_load_hsdfs(const UINT32 cdfs_md_id, const CSTRING *fname_cstr);
CBTREE * cbtree_load(const char *fname);

/*key_pos range from 0 to func_para_num - 1*/
EC_BOOL cbtree_scan(CBTREE *cbtree, 
                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *), 
                     const UINT32 func_para_num, const UINT32 key_pos,
                     const UINT32 handler_func_addr,...);

uint8_t *cbtree_make_kv(const char *row, const char *colf, const char *colq, const ctime_t ts, uint8_t type);

EC_BOOL cbtree_free_kv(uint8_t *kv);

#endif/* _CBTREE_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

