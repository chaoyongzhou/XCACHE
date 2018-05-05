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

#ifndef _CAGENT_H
#define _CAGENT_H

#include "type.h"
#include "mm.h"
#include "cmisc.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"

#include "json.h"

#include "chttp.h"
#include "chttps.h"
#include "ctdnshttp.h"

typedef struct
{
    CSTRING         tdns_host;
    UINT32          tdns_port;

    UINT32          reserved_tcid;
    UINT32          reserved_port;

    UINT32          local_ipaddr;
    UINT32          local_port; /*client socket port sending http request*/
}CAGENT;

#define CAGENT_TDNS_HOST(cagent)                (&((cagent)->tdns_host))
#define CAGENT_TDNS_PORT(cagent)                ((cagent)->tdns_port)

#define CAGENT_RESERVED_TCID(cagent)            ((cagent)->reserved_tcid)
#define CAGENT_RESERVED_PORT(cagent)            ((cagent)->reserved_port)

#define CAGENT_LOCAL_IPADDR(cagent)             ((cagent)->local_ipaddr)
#define CAGENT_LOCAL_PORT(cagent)               ((cagent)->local_port)

#define CAGENT_TDNS_HOST_STR(cagent)            (cstring_get_str(CAGENT_TDNS_HOST(cagent)))


CAGENT *cagent_new();

EC_BOOL cagent_init(CAGENT *cagent);

EC_BOOL cagent_clean(CAGENT *cagent);

EC_BOOL cagent_free(CAGENT *cagent);

void    cagent_print(LOG *log, const CAGENT *cagent);

EC_BOOL cagent_reserve_tcid(CAGENT *cagent, const char *service, const char *ipaddr);

EC_BOOL cagent_release_tcid(CAGENT *cagent, const char *service, const char *tcid, const char *port);

EC_BOOL cagent_check_config_xml(const CAGENT *cagent, const char *fname);

EC_BOOL cagent_gen_config_xml(const CAGENT *cagent, const char *fname);

SYS_CFG *cagent_gen_config(const CAGENT *cagent);

EC_BOOL cagent_set_service(CAGENT *cagent, const char *network_level, const char *service, const char *tcid, const char *ipaddr, const char *port);

EC_BOOL cagent_set_tcid(CAGENT *cagent, const char *tcid, const char *ipaddr, const char *port);

EC_BOOL cagent_check_p2p(const CAGENT *cagent);

EC_BOOL cagent_start_p2p(const CAGENT *cagent);

EC_BOOL cagent_stop_p2p(const CAGENT *cagent);

#endif/*_CAGENT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



