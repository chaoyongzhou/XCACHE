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

#ifndef _CDEVICE_H
#define _CDEVICE_H

#include "type.h"

#define CDEVICE_NETCARD_MAX_NUM 16

#define CNETCARD_UP_STATE        ((UINT32) 1)
#define CNETCARD_DOWN_STATE      ((UINT32) 2)
#define CNETCARD_ERR_STATE       ((UINT32)-1)

typedef struct
{
    CSTRING name;    /*device name*/
    CSTRING ipv4str; /*ip addr string*/
    UINT32  ipv4val; /*ip addr integer value*/
    CSTRING macstr;  /*mac string seperated by ':'*/
    UINT8   macaddr[6];
    UINT32  state;   /*UP or DOWN*/
}CNETCARD;

#define CNETCARD_NAME(cnetcard)     (&((cnetcard)->name))
#define CNETCARD_IPV4STR(cnetcard)  (&((cnetcard)->ipv4str))
#define CNETCARD_IPV4VAL(cnetcard)  ((cnetcard)->ipv4val)
#define CNETCARD_MACSTR(cnetcard)   (&((cnetcard)->macstr))
#define CNETCARD_MACADDR(cnetcard)  ((cnetcard)->macaddr)
#define CNETCARD_STATE(cnetcard)    ((cnetcard)->state)

CNETCARD * cnetcard_new();

UINT32 cnetcard_init(CNETCARD *cnetcard);

UINT32 cnetcard_clean(CNETCARD *cnetcard);

UINT32 cnetcard_free(CNETCARD *cnetcard);

EC_BOOL cnetcard_cmp_name(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd);

EC_BOOL cnetcard_cmp_ipv4str(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd);

EC_BOOL cnetcard_cmp_ipv4val(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd);

EC_BOOL cnetcard_cmp_macstr(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd);

EC_BOOL cnetcard_cmp_state(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd);

EC_BOOL cnetcard_cmp(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd);

EC_BOOL cnetcard_match_name(const CNETCARD *cnetcard_1st, const CSTRING *name);

EC_BOOL cnetcard_match_ipv4str(const CNETCARD *cnetcard_1st, const CSTRING *ipv4str);

EC_BOOL cnetcard_match_ipv4val(const CNETCARD *cnetcard_1st, const UINT32 ipv4val);

EC_BOOL cnetcard_match_macaddr(const CNETCARD *cnetcard_1st, const UINT8 *macaddr);

void cnetcard_print(LOG *log, const CNETCARD *cnetcard);

UINT32 cnetcard_collect(CSET *cnetcard_set, const UINT32 max_cnetcard_num);

EC_BOOL cnetcard_has_name(const CSET *cnetcard_set, const CSTRING *name);

EC_BOOL cnetcard_has_ipv4str(const CSET *cnetcard_set, const CSTRING *ipv4str);

EC_BOOL cnetcard_has_ipv4val(const CSET *cnetcard_set, const UINT32 ipv4val);

EC_BOOL cnetcard_has_macstr(const CSET *cnetcard_set, const CSTRING *macstr);

EC_BOOL cnetcard_has_state(const CSET *cnetcard_set, const UINT32 state);

CNETCARD * cnetcard_search_by_name(const CSET *cnetcard_set, const CSTRING *name);

CNETCARD * cnetcard_search_by_ipv4val(const CSET *cnetcard_set, const UINT32 ipv4val);

CNETCARD * cnetcard_search_by_ipv4str(const CSET *cnetcard_set, const CSTRING *ipv4str);

CNETCARD * cnetcard_search_by_macaddr(const CSET *cnetcard_set, const UINT8 *macaddr);


#endif /*_CDEVICE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

