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
#include <ctype.h>

#include "type.h"
#include "log.h"

#include "clist.h"
#include "cvector.h"
#include "cstring.h"

#include "mm.h"

#include "cmisc.h"
#include "taskcfg.inc"

#include "api_cmd.inc"
#include "api_cmd.h"

static const char *api_help_format = "\t%-16s\t\t%s\n";

static void api_ident_print(LOG *log, const UINT32 level)
{
    UINT32 idx;

    for(idx = 0; idx < level; idx ++)
    {
        sys_print(log, "    ");
    }
    return;
}

UINT8 *api_cmd_greedy_space(const UINT8 *pbeg, const UINT8 *pend)
{
    UINT8 *pch;

    if(NULL_PTR == pbeg || NULL_PTR == pend)
    {
        return (NULL_PTR);
    }

    for(pch = (UINT8 *)pbeg; pch < pend && 0 != isspace(*pch); pch ++)/*skip spaces*/
    {
        /*do nothing*/
    }

    if(pch >= pend)
    {
        return (NULL_PTR);
    }

    return (pch);
}

UINT8 * api_cmd_greedy_uint32(const UINT8 *pbeg, const UINT8 *pend, UINT32 *value)
{
    UINT8 *pch;
    UINT32 negs;
    UINT32 total;

    negs = 1;
    for(pch = (UINT8 *)pbeg; pch < pend && '-' == (*pch); pch ++)
    {
        negs *= ((UINT32)-1);
    }

    total = 0;
    for(; pch < pend; pch ++)
    {
        if((*pch) < '0' || (*pch) > '9')
        {
            break;
        }
        total = 10 * total + ((*pch) - '0');
    }

    (*value) = (total * negs);

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

UINT8 * api_cmd_greedy_real(const UINT8 *pbeg, const UINT8 *pend, REAL *value)
{
    UINT8  str[64];
    UINT8 *pch;
    UINT32 pos;

    for(pos = 0, pch = (UINT8 *)pbeg; pch < pend; pch ++, pos ++)
    {
        if(0 != isspace(*pch))
        {
            break;
        }
        str[ pos ] = (*pch);
    }
    str[ pos ] = '\0';

    (*value) = atof((char *)str);

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

UINT8 * api_cmd_greedy_tcid(const UINT8 *pbeg, const UINT8 *pend, UINT32 *tcid)
{
    UINT8 word[API_CMD_SEG_WORD_SIZE];
    UINT8 *pch;
    UINT32 pos;

    for(pos = 0, pch = (UINT8 *)pbeg; pch < pend && 0 == isspace(*pch) && pos + 1 < sizeof(word)/sizeof(word[0]); pch ++, pos ++)
    {
        word[ pos ] = (*pch);
    }
    word[ pos ] = '\0';

    (*tcid) = c_ipv4_to_word((char *)word);

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

UINT8 * api_cmd_greedy_mask(const UINT8 *pbeg, const UINT8 *pend, UINT32 *mask)
{
    UINT32 nbits;
    UINT8 *pcur;
#if 0
    UINT8 word[API_CMD_SEG_WORD_SIZE];
    UINT8 *pch;
    UINT32 pos;

    for(pos = 0, pch = (UINT8 *)pbeg; pch < pend && 0 == isspace(*pch) && pos + 1 < sizeof(word)/sizeof(word[0]); pch ++, pos ++)
    {
        word[ pos ] = (*pch);
    }
    word[ pos ] = '\0';

    (*mask) = c_ipv4_to_word((char *)word);

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
#endif
    pcur = api_cmd_greedy_uint32(pbeg, pend, &nbits);
    (*mask) = BITS_TO_MASK(nbits);
    return (pcur);
}

UINT8 * api_cmd_greedy_ipaddr(const UINT8 *pbeg, const UINT8 *pend, UINT32 *ipaddr)
{
    UINT8 word[API_CMD_SEG_WORD_SIZE];
    UINT8 *pch;
    UINT32 pos;

    for(pos = 0, pch = (UINT8 *)pbeg; pch < pend && 0 == isspace(*pch) && pos + 1 < sizeof(word)/sizeof(word[0]); pch ++, pos ++)
    {
        word[ pos ] = (*pch);
    }
    word[ pos ] = '\0';

    (*ipaddr) = c_ipv4_to_word((char *)word);

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

UINT8 * api_cmd_greedy_uint64(const UINT8 *pbeg, const UINT8 *pend, uint64_t *num)
{
    UINT8 word[API_CMD_SEG_WORD_SIZE];
    UINT8 *pch;
    UINT32 pos;

    for(pos = 0, pch = (UINT8 *)pbeg; pch < pend && 0 == isspace(*pch) && pos + 1 < sizeof(word)/sizeof(word[0]); pch ++, pos ++)
    {
        word[ pos ] = (*pch);
    }
    word[ pos ] = '\0';

    (*num) = c_str_to_uint64_t((char *)word);

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

UINT8 * api_cmd_greedy_cstring(const UINT8 *pbeg, const UINT8 *pend, CSTRING *cstring)
{
    UINT8 *pch;

    if('\'' == (*pbeg))
    {
        for(pch = ((UINT8 *)pbeg) + 1; pch < pend && '\'' != (*pch); pch ++)
        {
            cstring_append_char(cstring, (*pch));
        }

        if('\'' == (*pch))
        {
            pch ++;
        }
    }
    else
    {
        for(pch = (UINT8 *)pbeg; pch < pend && 0 == isspace(*pch); pch ++)
        {
            cstring_append_char(cstring, (*pch));
        }
    }

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

UINT8 *api_cmd_greedy_word(const UINT8 *pbeg, const UINT8 *pend, UINT8 *word, UINT32 max_len)
{
    UINT8 *pch;
    UINT32 pos;

    for(pos = 0, pch = (UINT8 *)pbeg; pch < pend && 0 == isspace(*pch) && pos + 1< max_len; pch ++, pos ++)
    {
        word[ pos ] = (*pch);
    }
    word[ pos ] = '\0';

    if(pch < pend)
    {
        return (pch);
    }
    return (NULL_PTR);
}

CMD_TREE *api_cmd_tree_new()
{
    CMD_TREE *cmd_tree;
    alloc_static_mem(MM_CLIST, &cmd_tree, LOC_API_0016);
    api_cmd_tree_init(cmd_tree);
    return (cmd_tree);
}

EC_BOOL api_cmd_tree_init(CMD_TREE *cmd_tree)
{
    clist_init(CMD_TREE_SEG_LIST(cmd_tree), MM_IGNORE, LOC_API_0017);
    return (EC_TRUE);
}

EC_BOOL api_cmd_tree_clean(CMD_TREE *cmd_tree)
{
    clist_clean(cmd_tree, (CLIST_DATA_DATA_CLEANER)api_cmd_seg_free);
    return (EC_TRUE);
}

EC_BOOL api_cmd_tree_free(CMD_TREE *cmd_tree)
{
    api_cmd_tree_clean(cmd_tree);
    free_static_mem(MM_CLIST, cmd_tree, LOC_API_0018);
    return (EC_TRUE);
}

CMD_SEG *api_cmd_tree_add(CMD_TREE *cmd_tree, const CMD_SEG *cmd_seg)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CMD_TREE_SEG_LIST(cmd_tree), clist_data)
    {
        CMD_SEG *cur_cmd_seg;
        cur_cmd_seg = (CMD_SEG *)CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == api_cmd_seg_cmp(cmd_seg, cur_cmd_seg))
        {
            return (cur_cmd_seg);
        }

        if(CMD_SEG_TYPE_KEYWORD != CMD_SEG_TYPE(cmd_seg) && CMD_SEG_TYPE_KEYWORD != CMD_SEG_TYPE(cur_cmd_seg))
        {
            dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_tree_add: non submemu word %s has already defined in this level\n",
                                (char *)CMD_SEG_WORD(cur_cmd_seg));
            return (NULL_PTR);
        }
    }

    clist_push_back(CMD_TREE_SEG_LIST(cmd_tree), (void *)cmd_seg);
    return ((CMD_SEG *)cmd_seg);
}

EC_BOOL api_cmd_tree_define(CMD_TREE *cmd_tree, CMD_HANDLER cmd_handler, const UINT8 *cmd_fmt, va_list ap)
{
    UINT8 *safe_cmd_fmt;
    CMD_SEG *cmd_seg_new;
    CMD_SEG *cmd_seg_ret;

    safe_cmd_fmt = (UINT8 *)cmd_fmt;
    if(NULL_PTR == safe_cmd_fmt)
    {
        return (EC_TRUE);
    }

    cmd_seg_new = api_cmd_seg_new();
    api_cmd_seg_fetch(cmd_seg_new, safe_cmd_fmt, &safe_cmd_fmt, ap);

    cmd_seg_ret = api_cmd_tree_add(cmd_tree, cmd_seg_new);
    if(NULL_PTR == cmd_seg_ret)/*fail*/
    {
        api_cmd_seg_free(cmd_seg_new);
        return (EC_FALSE);
    }

    if(cmd_seg_ret != cmd_seg_new)/*exist*/
    {
        api_cmd_seg_free(cmd_seg_new);
    }

    if(NULL_PTR != safe_cmd_fmt)
    {
        if(NULL_PTR == CMD_SEG_SUB_TREE(cmd_seg_ret))
        {
            CMD_SEG_SUB_TREE(cmd_seg_ret) = api_cmd_tree_new();
        }

        if(NULL_PTR == CMD_SEG_SUB_TREE(cmd_seg_ret))
        {
            dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_tree_define:subtree is null\n");
            return (EC_FALSE);
        }

        return api_cmd_tree_define(CMD_SEG_SUB_TREE(cmd_seg_ret), cmd_handler, safe_cmd_fmt, ap);
    }

    if(NULL_PTR != CMD_SEG_HANDLER(cmd_seg_ret))
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_tree_define: handler was already defined\n");
        return (EC_FALSE);
    }

    CMD_SEG_HANDLER(cmd_seg_ret) = cmd_handler;
    return (EC_TRUE);
}

EC_BOOL api_cmd_tree_parse(const CMD_TREE *cmd_tree, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec)
{
    UINT8 word[API_CMD_SEG_WORD_SIZE];
    CLIST_DATA *clist_data;

    dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_tree_parse => cmd_line = %s\n", (char *)cmd_line);
    api_cmd_greedy_word(cmd_line, cmd_line + strlen((char *)cmd_line), word, API_CMD_SEG_WORD_SIZE);/*probe*/
    dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_tree_parse => word = %s\n", (char *)word);

    CLIST_LOOP_NEXT(CMD_TREE_SEG_LIST(cmd_tree), clist_data)
    {
        CMD_SEG *cmd_seg;

        cmd_seg = (CMD_SEG *)CLIST_DATA_DATA(clist_data);
        dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_tree_parse => check word %s\n", (char *)CMD_SEG_WORD(cmd_seg));
        if(CMD_SEG_TYPE_KEYWORD != CMD_SEG_TYPE(cmd_seg))
        {
            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_tree_parse => type %ld, word %s\n", CMD_SEG_TYPE(cmd_seg), (char *)CMD_SEG_WORD(cmd_seg));
            return api_cmd_seg_parse(cmd_seg, cmd_line, cmd_para_vec);
        }

        if(0 == strncasecmp((char *)CMD_SEG_WORD(cmd_seg), (char *)word, API_CMD_SEG_WORD_SIZE))
        {
            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_tree_parse => keyword\n");
            return api_cmd_seg_parse(cmd_seg, cmd_line, cmd_para_vec);
        }
    }
    dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "invalid syntax: %s\n", (char *)cmd_line);
    return (EC_FALSE);
}

void api_cmd_tree_print(LOG *log, const CMD_TREE *cmd_tree, const UINT32 level)
{
    CLIST_DATA *clist_data;
    api_ident_print(log, level);

    CLIST_LOOP_NEXT(CMD_TREE_SEG_LIST(cmd_tree), clist_data)
    {
        CMD_SEG *cmd_seg;

        cmd_seg = (CMD_SEG *)CLIST_DATA_DATA(clist_data);
        api_cmd_seg_print(log, cmd_seg, level);
    }
    return;
}

CMD_SEG *api_cmd_seg_new()
{
    CMD_SEG *cmd_seg;

    alloc_static_mem(MM_CMD_SEG, &cmd_seg, LOC_API_0019);
    api_cmd_seg_init(cmd_seg);
    return (cmd_seg);
}

EC_BOOL api_cmd_seg_init(CMD_SEG *cmd_seg)
{
    UINT32 pos;

    for(pos = 0; pos < API_CMD_SEG_WORD_SIZE; pos ++)
    {
        CMD_SEG_WORD_CHAR(cmd_seg, pos) = '\0';
    }
    CMD_SEG_TYPE(cmd_seg)     = CMD_SEG_TYPE_NULL;
    CMD_SEG_SUB_TREE(cmd_seg) = NULL_PTR;
    CMD_SEG_HANDLER(cmd_seg)  = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL api_cmd_seg_clean(CMD_SEG *cmd_seg)
{
    UINT32 pos;

    for(pos = 0; pos < API_CMD_SEG_WORD_SIZE; pos ++)
    {
        CMD_SEG_WORD_CHAR(cmd_seg, pos) = '\0';
    }
    CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_NULL;

    if(NULL_PTR != CMD_SEG_SUB_TREE(cmd_seg))
    {
        api_cmd_tree_free(CMD_SEG_SUB_TREE(cmd_seg));
        CMD_SEG_SUB_TREE(cmd_seg) = NULL_PTR;
    }

    CMD_SEG_HANDLER(cmd_seg) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL api_cmd_seg_free(CMD_SEG *cmd_seg)
{
    api_cmd_seg_clean(cmd_seg);
    free_static_mem(MM_CMD_SEG, cmd_seg, LOC_API_0020);
    return (EC_TRUE);
}

EC_BOOL api_cmd_seg_cmp(const CMD_SEG *cmd_seg_1st, const CMD_SEG *cmd_seg_2nd)
{
    if(CMD_SEG_TYPE(cmd_seg_1st) != CMD_SEG_TYPE(cmd_seg_2nd))
    {
        return (EC_FALSE);
    }

    /*ignoring the case of the characters*/
    if(0 != strncasecmp((char *)CMD_SEG_WORD(cmd_seg_1st), (char *)CMD_SEG_WORD(cmd_seg_2nd), API_CMD_SEG_WORD_SIZE))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void api_cmd_seg_print(LOG *log, const CMD_SEG *cmd_seg, const UINT32 level)
{
    api_ident_print(log, level);
    sys_print(log, "type = %ld, word = %s\n",
                    CMD_SEG_TYPE(cmd_seg),
                    (char *)CMD_SEG_WORD(cmd_seg)                    );

    if(NULL_PTR != CMD_SEG_SUB_TREE(cmd_seg))
    {
        api_cmd_tree_print(log, CMD_SEG_SUB_TREE(cmd_seg), level + 1);
    }
    return;
}

/*fetch word token*/
EC_BOOL api_cmd_seg_fetch(CMD_SEG *cmd_seg, const UINT8 *cmd_fmt, UINT8 **next_cmd_fmt, va_list ap)
{
    UINT8 *pbeg;
    UINT8 *pend;
    UINT8 *pch;
    UINT8 *token;
    UINT32 pos;

    pbeg = (UINT8 *)cmd_fmt;
    pend = (UINT8 *)cmd_fmt + strlen((char *)cmd_fmt);
    pch  = api_cmd_greedy_space(pbeg, pend);

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pch < pend && 0 == isspace(*pch); pos ++, pch ++)
    {
        CMD_SEG_WORD_CHAR(cmd_seg, pos) = (*pch);
    }
    CMD_SEG_WORD_CHAR(cmd_seg, pos) = '\0';

    if(pch >= pend)
    {
        (*next_cmd_fmt) = NULL_PTR;
    }
    else
    {
        (*next_cmd_fmt) = pch;
    }

    token = CMD_SEG_WORD_CHAR_PTR(cmd_seg, 0);
    if('%' != token[0])
    {
        CMD_SEG_TYPE(cmd_seg)  = CMD_SEG_TYPE_KEYWORD;
        CMD_SEG_ELEM(cmd_seg)  = NULL_PTR;
        return (EC_TRUE);
    }

    /* Determine which token was found */
    if (0 == strncmp((char *)token, "%f", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_REAL;
        CMD_SEG_ELEM(cmd_seg) = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%l", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_LIST;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%n", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_INTEGER;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%r", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_RANGE;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%s", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_CSTRING;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%t", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_TCID;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%m", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_MASK;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }
    if (0 == strncmp((char *)token,"%p", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_IPADDR;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    }

    if (0 == strncmp((char *)token,"%N", 2))
    {
        CMD_SEG_TYPE(cmd_seg) = CMD_SEG_TYPE_UINT64;
        CMD_SEG_ELEM(cmd_seg)  = va_arg(ap, CMD_ELEM *);
        return (EC_TRUE);
    } 

    CMD_SEG_TYPE(cmd_seg)  = CMD_SEG_TYPE_NULL;
    CMD_SEG_ELEM(cmd_seg)  = NULL_PTR;
    dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_seg_fetch: unknow token %s\n", (char *)token);
    return (EC_FALSE);
}

EC_BOOL api_cmd_seg_handle(const CMD_SEG *cmd_seg, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec)
{
    UINT8 *pbeg;
    UINT8 *pend;
    UINT8 *pcur;

    if(NULL_PTR == cmd_line)
    {
        dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_handle => cmd_line is null\n");
        if(NULL_PTR == CMD_SEG_HANDLER(cmd_seg))
        {
            dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_seg_handle: no handler defined\n");
            return (EC_FALSE);
        }

        return CMD_SEG_HANDLER(cmd_seg)(cmd_para_vec);
    }

    pbeg = (UINT8 *)cmd_line;
    pend = (UINT8 *)cmd_line + strlen((char *)cmd_line);
    pcur  = api_cmd_greedy_space(pbeg, pend);

    pcur = api_cmd_greedy_space(pcur, pend);
    if(NULL_PTR == pcur)
    {
        dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_handle => pcur is null, cmd_line = %s\n", (char *)cmd_line);
        if(NULL_PTR == CMD_SEG_HANDLER(cmd_seg))
        {
            dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_seg_handle: no handler defined\n");
            return (EC_FALSE);
        }

        return CMD_SEG_HANDLER(cmd_seg)(cmd_para_vec);
    }

    if(NULL_PTR == CMD_SEG_SUB_TREE(cmd_seg))
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_seg_handle: no parser for %s\n", (char *)pcur);
        return (EC_FALSE);
    }

    dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_handle => subtree\n");
    return api_cmd_tree_parse(CMD_SEG_SUB_TREE(cmd_seg), pcur, cmd_para_vec);
}

EC_BOOL api_cmd_seg_parse(const CMD_SEG *cmd_seg, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec)
{
    UINT8 *pbeg;
    UINT8 *pend;
    UINT8 *pcur;

    pbeg = (UINT8 *)cmd_line;
    pend = (UINT8 *)cmd_line + strlen((char *)cmd_line);
    pcur  = api_cmd_greedy_space(pbeg, pend);

    switch(CMD_SEG_TYPE(cmd_seg))
    {
        case CMD_SEG_TYPE_KEYWORD :
        {
            pcur += strlen((char *)CMD_SEG_WORD(cmd_seg));
            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => keyword, word %s, left %s\n", (char *)CMD_SEG_WORD(cmd_seg), (char *)pcur);
            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
        case CMD_SEG_TYPE_INTEGER :
        {
            CMD_PARA *cmd_para;
            UINT32 value;

            pcur = api_cmd_greedy_uint32(pcur, pend, &value);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_uint32(cmd_para, value);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => integer, left %s\n", (char *)pcur);
            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
        case CMD_SEG_TYPE_UINT64    :
        {
            CMD_PARA *cmd_para;
            uint64_t value;

            pcur = api_cmd_greedy_uint64(pcur, pend, &value);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_uint64(cmd_para, value);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => uint64_t, left %s\n", (char *)pcur);
            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }      
        case CMD_SEG_TYPE_REAL    :
        {
            CMD_PARA *cmd_para;
            REAL value;

            pcur = api_cmd_greedy_real(pcur, pend, &value);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_real(cmd_para, &value);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => real, left %s\n", (char *)pcur);

            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
        case CMD_SEG_TYPE_CSTRING :
        {
            CMD_PARA *cmd_para;
            CSTRING *cstring;

            cstring = cstring_new(NULL_PTR, LOC_API_0021);
            pcur = api_cmd_greedy_cstring(pcur, pend, cstring);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_cstring(cmd_para, cstring);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => cstring, left %s\n", (char *)pcur);

            api_cmd_para_vec_print(LOGSTDNULL, cmd_para_vec);

            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
        case CMD_SEG_TYPE_TCID    :
        {
            CMD_PARA *cmd_para;
            UINT32 tcid;

            pcur = api_cmd_greedy_tcid(pcur, pend, &tcid);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_uint32(cmd_para, tcid);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => tcid, left %s\n", (char *)pcur);
            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
        case CMD_SEG_TYPE_MASK    :
        {
            CMD_PARA *cmd_para;
            UINT32 mask;

            pcur = api_cmd_greedy_mask(pcur, pend, &mask);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_uint32(cmd_para, mask);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => mask, left %s\n", (char *)pcur);
            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
        case CMD_SEG_TYPE_IPADDR    :
        {
            CMD_PARA *cmd_para;
            UINT32 ipaddr;

            pcur = api_cmd_greedy_ipaddr(pcur, pend, &ipaddr);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_uint32(cmd_para, ipaddr);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => ipaddr, left %s\n", (char *)pcur);
            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }   
        case CMD_SEG_TYPE_LIST:
        {
            CMD_PARA *cmd_para;
            CSTRING *cstring;
            UINT32 value;

            cstring = cstring_new(NULL_PTR, LOC_API_0022);
            pcur = api_cmd_greedy_cstring(pcur, pend, cstring);

            api_cmd_elem_find_list_item(CMD_SEG_ELEM(cmd_seg), (char *)cstring_get_str(cstring), &value);
            cstring_free(cstring);

            cmd_para = api_cmd_para_new();
            api_cmd_para_set_uint32(cmd_para, value);
            api_cmd_para_vec_add(cmd_para_vec, cmd_para);

            dbg_log(SEC_0010_API, 9)(LOGSTDNULL, "[DEBUG] api_cmd_seg_parse => list, left %s\n", (char *)pcur);
            api_cmd_para_vec_print(LOGSTDNULL, cmd_para_vec);

            return api_cmd_seg_handle(cmd_seg, pcur, cmd_para_vec);
        }
    }
    dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_seg_parse: not support seg type %ld\n", CMD_SEG_TYPE(cmd_seg));
    return (EC_FALSE);
}

CMD_PARA *api_cmd_para_new()
{
    CMD_PARA *cmd_para;

    alloc_static_mem(MM_CMD_PARA, &cmd_para, LOC_API_0023);
    api_cmd_para_init(cmd_para);
    return (cmd_para);
}

EC_BOOL api_cmd_para_init(CMD_PARA *cmd_para)
{
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_NULL;
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_clean(CMD_PARA *cmd_para)
{
    switch(CMD_PARA_TYPE(cmd_para))
    {
        case CMD_PARA_TYPE_INTEGER:
            CMD_PARA_UINT32(cmd_para) = 0;
            break;
        case CMD_PARA_TYPE_REAL:
            CMD_PARA_REAL(cmd_para) = 0.0;
            break;
        case CMD_PARA_TYPE_CSTRING:
            if(NULL_PTR != CMD_PARA_CSTRING(cmd_para))
            {
                cstring_free(CMD_PARA_CSTRING(cmd_para));
                CMD_PARA_CSTRING(cmd_para) = NULL_PTR;
            }
            break;
    }
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_NULL;
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_free(CMD_PARA *cmd_para)
{
    api_cmd_para_clean(cmd_para);
    free_static_mem(MM_CMD_PARA, cmd_para, LOC_API_0024);
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_set_uint32(CMD_PARA *cmd_para, const UINT32 value)
{
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_INTEGER;
    CMD_PARA_UINT32(cmd_para) = value;
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_set_uint64(CMD_PARA *cmd_para, const uint64_t value)
{
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_INTEGER;
    CMD_PARA_UINT64(cmd_para) = value;
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_set_tcid(CMD_PARA *cmd_para, const UINT32 tcid)
{
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_INTEGER;
    CMD_PARA_UINT32(cmd_para) = tcid;
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_set_real(CMD_PARA *cmd_para, const REAL *value)
{
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_REAL;
    CMD_PARA_REAL(cmd_para) = (*value);
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_set_cstring(CMD_PARA *cmd_para, CSTRING *cstring)
{
    CMD_PARA_TYPE(cmd_para) = CMD_PARA_TYPE_CSTRING;
    CMD_PARA_CSTRING(cmd_para) = cstring;
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_get_uint32(const CMD_PARA *cmd_para, UINT32 *value)
{
    if(CMD_PARA_TYPE_INTEGER == CMD_PARA_TYPE(cmd_para))
    {
        (*value) = CMD_PARA_UINT32(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_para_get_uint64(const CMD_PARA *cmd_para, uint64_t *value)
{
    if(CMD_PARA_TYPE_INTEGER == CMD_PARA_TYPE(cmd_para))
    {
        (*value) = CMD_PARA_UINT64(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_para_get_tcid(const CMD_PARA *cmd_para, UINT32 *tcid)
{
    if(CMD_PARA_TYPE_INTEGER == CMD_PARA_TYPE(cmd_para))
    {
        (*tcid) = CMD_PARA_UINT32(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_para_get_mask(const CMD_PARA *cmd_para, UINT32 *mask)
{
    if(CMD_PARA_TYPE_INTEGER == CMD_PARA_TYPE(cmd_para))
    {
        (*mask) = CMD_PARA_UINT32(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_para_get_ipaddr(const CMD_PARA *cmd_para, UINT32 *ipaddr)
{
    if(CMD_PARA_TYPE_INTEGER == CMD_PARA_TYPE(cmd_para))
    {
        (*ipaddr) = CMD_PARA_UINT32(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_para_get_real(const CMD_PARA *cmd_para, REAL *value)
{
    if(CMD_PARA_TYPE_REAL == CMD_PARA_TYPE(cmd_para))
    {
        (*value) = CMD_PARA_REAL(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void api_cmd_para_print(LOG *log, const CMD_PARA *cmd_para)
{
    switch(CMD_PARA_TYPE(cmd_para))
    {
        case CMD_PARA_TYPE_INTEGER:
            sys_log(log, "type %ld, value %ld\n", CMD_PARA_TYPE(cmd_para), CMD_PARA_UINT32(cmd_para));
            return;
        case CMD_PARA_TYPE_CSTRING:
            sys_log(log, "type %ld, value %s\n", CMD_PARA_TYPE(cmd_para), (char *)cstring_get_str(CMD_PARA_CSTRING(cmd_para)));
            return;
    }
    sys_log(log, "api_cmd_para_print: not support cmd para type %ld\n", CMD_PARA_TYPE(cmd_para));
    return;
}

EC_BOOL api_cmd_para_get_cstring(const CMD_PARA *cmd_para, CSTRING **cstring)
{
    if(CMD_PARA_TYPE_CSTRING == CMD_PARA_TYPE(cmd_para))
    {
        (*cstring) = CMD_PARA_CSTRING(cmd_para);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

CMD_PARA_VEC *api_cmd_para_vec_new()
{
    CMD_PARA_VEC *cmd_para_vec;
    alloc_static_mem(MM_CVECTOR, &cmd_para_vec, LOC_API_0025);
    api_cmd_para_vec_init(cmd_para_vec);
    return (cmd_para_vec);
}

EC_BOOL api_cmd_para_vec_init(CMD_PARA_VEC *cmd_para_vec)
{
    cvector_init(CMD_PARA_VAL_LIST(cmd_para_vec), 0, MM_CMD_PARA, CVECTOR_LOCK_ENABLE, LOC_API_0026);
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_vec_clean(CMD_PARA_VEC *cmd_para_vec)
{
    cvector_clean(CMD_PARA_VAL_LIST(cmd_para_vec), (CLIST_DATA_DATA_CLEANER)api_cmd_para_free, LOC_API_0027);
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_vec_free(CMD_PARA_VEC *cmd_para_vec)
{
    api_cmd_para_vec_clean(cmd_para_vec);
    free_static_mem(MM_CVECTOR, cmd_para_vec, LOC_API_0028);
    return (EC_TRUE);
}

EC_BOOL api_cmd_para_vec_get_uint32(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *value)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_uint32: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_uint32(cmd_para, value);
}

EC_BOOL api_cmd_para_vec_get_uint64(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, uint64_t *value)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_uint64: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_uint64(cmd_para, value);
}

EC_BOOL api_cmd_para_vec_get_tcid(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *tcid)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_tcid: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_tcid(cmd_para, tcid);
}

EC_BOOL api_cmd_para_vec_get_mask(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *mask)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_mask: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_mask(cmd_para, mask);
}

EC_BOOL api_cmd_para_vec_get_ipaddr(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, UINT32 *ipaddr)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_ipaddr: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_ipaddr(cmd_para, ipaddr);
}

EC_BOOL api_cmd_para_vec_get_real(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, REAL *value)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_real: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_real(cmd_para, value);
}

EC_BOOL api_cmd_para_vec_get_cstring(const CMD_PARA_VEC *cmd_para_vec, const UINT32 pos, CSTRING **cstring)
{
    CMD_PARA *cmd_para;

    cmd_para = (CMD_PARA *)cvector_get(CMD_PARA_VAL_LIST(cmd_para_vec), pos);
    if(NULL_PTR == cmd_para)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_para_vec_get_cstring: CMD_PARA_VAL_LIST is null at pos %ld\n", pos);
        return (EC_FALSE);
    }

    return api_cmd_para_get_cstring(cmd_para, cstring);
}

EC_BOOL api_cmd_para_vec_add(CMD_PARA_VEC *cmd_para_vec, const CMD_PARA *cmd_para)
{
    cvector_push(CMD_PARA_VAL_LIST(cmd_para_vec), (void *)cmd_para);
    return (EC_TRUE);
}

void api_cmd_para_vec_print(LOG *log, const CMD_PARA_VEC *cmd_para_vec)
{
    cvector_print(log, CMD_PARA_VAL_LIST(cmd_para_vec), (CVECTOR_DATA_PRINT)api_cmd_para_print);
    return;
}

CMD_HELP *api_cmd_help_new()
{
    CMD_HELP *cmd_help;
    alloc_static_mem(MM_CMD_HELP, &cmd_help, LOC_API_0029);
    api_cmd_help_init(cmd_help);
    return (cmd_help);
}

EC_BOOL api_cmd_help_init(CMD_HELP *cmd_help)
{
    CMD_HELP_ABBR(cmd_help)     = NULL_PTR;
    CMD_HELP_SYNTAX(cmd_help)   = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_clean(CMD_HELP *cmd_help)
{
    CMD_HELP_ABBR(cmd_help)     = NULL_PTR;
    CMD_HELP_SYNTAX(cmd_help)   = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_free(CMD_HELP *cmd_help)
{
    api_cmd_help_clean(cmd_help);
    free_static_mem(MM_CMD_HELP, cmd_help, LOC_API_0030);
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_set(CMD_HELP *cmd_help, const char *cmd_help_abbr, const char *cmd_help_syntax)
{
    CMD_HELP_ABBR(cmd_help)     = (UINT8 *)cmd_help_abbr;
    CMD_HELP_SYNTAX(cmd_help)   = (UINT8 *)cmd_help_syntax;
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_cmp(CMD_HELP *cmd_help_1st, CMD_HELP *cmd_help_2nd)
{
    if(0 != strcasecmp((char *)CMD_HELP_ABBR(cmd_help_1st), (char *)CMD_HELP_ABBR(cmd_help_2nd)))
    {
        return (EC_FALSE);
    }

    if(0 != strcasecmp((char *)CMD_HELP_SYNTAX(cmd_help_1st), (char *)CMD_HELP_SYNTAX(cmd_help_2nd)))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void api_cmd_help_print(LOG *log, const CMD_HELP *cmd_help)
{
    sys_print(log, api_help_format, CMD_HELP_ABBR(cmd_help), CMD_HELP_SYNTAX(cmd_help));
    return;
}

CMD_HELP_VEC *api_cmd_help_vec_new()
{
    CMD_HELP_VEC *cmd_help_vec;
    alloc_static_mem(MM_CVECTOR, &cmd_help_vec, LOC_API_0031);
    api_cmd_help_vec_init(cmd_help_vec);
    return (cmd_help_vec);
}

EC_BOOL api_cmd_help_vec_init(CMD_HELP_VEC *cmd_help_vec)
{
    cvector_init(CMD_HELP_NODE_VEC(cmd_help_vec), 0, MM_CMD_HELP, CVECTOR_LOCK_ENABLE, LOC_API_0032);
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_vec_clean(CMD_HELP_VEC *cmd_help_vec)
{
    cvector_clean(CMD_HELP_NODE_VEC(cmd_help_vec), (CLIST_DATA_DATA_CLEANER)api_cmd_help_free, LOC_API_0033);
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_vec_free(CMD_HELP_VEC *cmd_help_vec)
{
    api_cmd_help_vec_clean(cmd_help_vec);
    free_static_mem(MM_CVECTOR, cmd_help_vec, LOC_API_0034);
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_vec_add(CMD_HELP_VEC *cmd_help_vec, const CMD_HELP *cmd_help)
{
    if(CVECTOR_ERR_POS != cvector_search_front(CMD_HELP_NODE_VEC(cmd_help_vec), (void *)cmd_help, (CVECTOR_DATA_CMP)api_cmd_help_cmp))
    {
        return (EC_FALSE);
    }

    cvector_push(CMD_HELP_NODE_VEC(cmd_help_vec), (void *)cmd_help);
    return (EC_TRUE);
}

EC_BOOL api_cmd_help_vec_create(CMD_HELP_VEC *cmd_help_vec, const char *cmd_help_abbr, const char *cmd_help_syntax)
{
    CMD_HELP *cmd_help;

    cmd_help = api_cmd_help_new();
    api_cmd_help_set(cmd_help, cmd_help_abbr, cmd_help_syntax);

    if(EC_FALSE == api_cmd_help_vec_add(cmd_help_vec, cmd_help))
    {
        api_cmd_help_free(cmd_help);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void api_cmd_help_vec_print(LOG *log, const CMD_HELP_VEC *cmd_help_vec)
{
    UINT32 pos;

    for(pos = 0; pos < cvector_size(CMD_HELP_NODE_VEC(cmd_help_vec)); pos ++)
    {
        CMD_HELP *cmd_help;

        cmd_help = (CMD_HELP *)cvector_get(CMD_HELP_NODE_VEC(cmd_help_vec), pos);
        if(NULL_PTR == cmd_help)
        {
            continue;
        }

        api_cmd_help_print(log, cmd_help);
    }

    return;
}

CMD_ELEM *api_cmd_elem_new()
{
    CMD_ELEM *cmd_elem;

    alloc_static_mem(MM_CMD_ELEM, &cmd_elem, LOC_API_0035);
    api_cmd_elem_init(cmd_elem);
    return (cmd_elem);
}

EC_BOOL api_cmd_elem_init(CMD_ELEM *cmd_elem)
{
    UINT32 pos;
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_NULL;
    for(pos = 0; pos < API_CMD_SEG_WORD_SIZE; pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';
    }
    return (EC_TRUE);
}

EC_BOOL api_cmd_elem_clean(CMD_ELEM *cmd_elem)
{
    UINT32 pos;

    switch(CMD_ELEM_TYPE(cmd_elem))
    {
        case CMD_PARA_TYPE_INTEGER:
            CMD_ELEM_UINT32(cmd_elem) = 0;
            break;
        case CMD_PARA_TYPE_REAL:
            CMD_ELEM_REAL(cmd_elem) = 0.0;
            break;
        case CMD_PARA_TYPE_CSTRING:
            if(NULL_PTR != CMD_ELEM_CSTRING(cmd_elem))
            {
                cstring_free(CMD_ELEM_CSTRING(cmd_elem));
                CMD_ELEM_CSTRING(cmd_elem) = NULL_PTR;
            }
            break;
        case CMD_PARA_TYPE_LIST:
            if(NULL_PTR != CMD_ELEM_VEC(cmd_elem))
            {
                cvector_clean(CMD_ELEM_VEC(cmd_elem), (CVECTOR_DATA_CLEANER)api_cmd_elem_free, LOC_API_0036);
                cvector_free(CMD_ELEM_VEC(cmd_elem), LOC_API_0037);
                CMD_ELEM_VEC(cmd_elem) = NULL_PTR;
            }
            break;
    }
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_NULL;
    for(pos = 0; pos < API_CMD_SEG_WORD_SIZE; pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';
    }
    return (EC_TRUE);
}

EC_BOOL api_cmd_elem_free(CMD_ELEM *cmd_elem)
{
    api_cmd_elem_clean(cmd_elem);
    free_static_mem(MM_CMD_ELEM, cmd_elem, LOC_API_0038);
    return (EC_TRUE);
}

CMD_ELEM *api_cmd_elem_create_uint32(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_INTEGER;
    CMD_ELEM_UINT32(cmd_elem) = 0;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}

CMD_ELEM *api_cmd_elem_create_uint64(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_INTEGER;
    CMD_ELEM_UINT64(cmd_elem) = 0;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}


CMD_ELEM *api_cmd_elem_create_cstring(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_CSTRING;
    CMD_ELEM_CSTRING(cmd_elem) = NULL_PTR;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}

CMD_ELEM *api_cmd_elem_create_tcid(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_TCID;
    CMD_ELEM_UINT32(cmd_elem) = 0;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}

CMD_ELEM *api_cmd_elem_create_mask(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_MASK;
    CMD_ELEM_UINT32(cmd_elem) = 0;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}

CMD_ELEM *api_cmd_elem_create_ipaddr(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_IPADDR;
    CMD_ELEM_UINT32(cmd_elem) = 0;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}

CMD_ELEM *api_cmd_elem_create_list(const char *word)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_LIST;
    CMD_ELEM_VEC(cmd_elem)  = cvector_new(0, MM_CMD_ELEM, LOC_API_0039);

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    return (cmd_elem);
}

CMD_ELEM *api_cmd_elem_create_list_item(CMD_ELEM *cmd_elem_list, const char *word, const UINT32 value)
{
    CMD_ELEM *cmd_elem;
    UINT32 pos;

    cmd_elem = api_cmd_elem_new();
    CMD_ELEM_TYPE(cmd_elem) = CMD_PARA_TYPE_LIST_ITEM;
    CMD_ELEM_UINT32(cmd_elem) = value;

    for(pos = 0; pos + 1 < API_CMD_SEG_WORD_SIZE && pos < strlen(word); pos ++)
    {
        CMD_ELEM_WORD_CHAR(cmd_elem, pos) = *(word + pos);
    }
    CMD_ELEM_WORD_CHAR(cmd_elem, pos) = '\0';

    cvector_push(CMD_ELEM_VEC(cmd_elem_list), (void *)cmd_elem);

    return (cmd_elem);
}

EC_BOOL api_cmd_elem_find_list_item(CMD_ELEM *cmd_elem_list, const char *word, UINT32 *value)
{
    UINT32 cmd_elem_pos;

    for(cmd_elem_pos = 0; cmd_elem_pos < cvector_size(CMD_ELEM_VEC(cmd_elem_list)); cmd_elem_pos ++)
    {
        CMD_ELEM *cmd_elem;
        cmd_elem = (CMD_ELEM *)cvector_get(CMD_ELEM_VEC(cmd_elem_list), cmd_elem_pos);

        if(0 == strncasecmp((char *)CMD_ELEM_WORD(cmd_elem), word, API_CMD_SEG_WORD_SIZE))
        {
            (*value) = CMD_ELEM_UINT32(cmd_elem);
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

CMD_ELEM_VEC *api_cmd_elem_vec_new()
{
    CMD_ELEM_VEC *cmd_elem_vec;
    alloc_static_mem(MM_CVECTOR, &cmd_elem_vec, LOC_API_0040);
    api_cmd_elem_vec_init(cmd_elem_vec);
    return (cmd_elem_vec);
}

EC_BOOL api_cmd_elem_vec_init(CMD_ELEM_VEC *cmd_elem_vec)
{
    cvector_init(CMD_ELEM_NODE_VEC(cmd_elem_vec), 0, MM_CMD_ELEM, CVECTOR_LOCK_ENABLE, LOC_API_0041);
    return (EC_TRUE);
}

EC_BOOL api_cmd_elem_vec_clean(CMD_ELEM_VEC *cmd_elem_vec)
{
    cvector_clean(CMD_ELEM_NODE_VEC(cmd_elem_vec), (CLIST_DATA_DATA_CLEANER)api_cmd_elem_free, LOC_API_0042);
    return (EC_TRUE);
}

EC_BOOL api_cmd_elem_vec_free(CMD_ELEM_VEC *cmd_elem_vec)
{
    api_cmd_elem_vec_clean(cmd_elem_vec);
    free_static_mem(MM_CVECTOR, cmd_elem_vec, LOC_API_0043);
    return (EC_TRUE);
}

EC_BOOL api_cmd_elem_vec_add(CMD_ELEM_VEC *cmd_elem_vec, const CMD_ELEM *cmd_elem)
{
    cvector_push(CMD_ELEM_NODE_VEC(cmd_elem_vec), (void *)cmd_elem);
    return (EC_TRUE);
}

EC_BOOL api_cmd_comm_define(CMD_TREE *cmd_tree, CMD_HANDLER cmd_handler, const char *cmd_fmt, ...)
{
    va_list ap;
    EC_BOOL ret;

    va_start(ap, cmd_fmt);
    ret = api_cmd_tree_define(cmd_tree, cmd_handler, (UINT8 *)cmd_fmt, ap);
    va_end(ap);

    return (ret);
}

EC_BOOL api_cmd_comm_help(LOG *log, const CMD_HELP_VEC *cmd_help_vec)
{
    sys_print(log, api_help_format, "command abbr.", "command syntax");
    sys_print(log, "---------------------------------------------------------------------------------------------------\n");

    api_cmd_help_vec_print(log, cmd_help_vec);
    return (EC_TRUE);
}

EC_BOOL api_cmd_comm_parse(const CMD_TREE *cmd_tree, const UINT8 *cmd_line, CMD_PARA_VEC *cmd_para_vec)
{
    if(EC_FALSE == api_cmd_tree_parse(cmd_tree, cmd_line, cmd_para_vec))
    {
        dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "invalid syntax: %s\n", (char *)cmd_line);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

