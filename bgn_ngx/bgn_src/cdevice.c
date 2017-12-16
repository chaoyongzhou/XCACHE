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
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <sys/sysinfo.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "type.h"
#include "mm.h"

#include "cset.h"
#include "cdevice.h"
#include "csocket.h"

#include "cmisc.h"

#include "log.h"


CNETCARD * cnetcard_new()
{
    CNETCARD *cnetcard;

    cnetcard = (CNETCARD *)SAFE_MALLOC(sizeof(CNETCARD), LOC_CDEVICE_0001);
    if(NULL_PTR == cnetcard)
    {
        dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_new: failed to malloc CNETCARD\n");
        return (NULL_PTR);
    }
    cnetcard_init(cnetcard);
    return (cnetcard);
}

UINT32 cnetcard_init(CNETCARD *cnetcard)
{
    cstring_init(CNETCARD_NAME(cnetcard), NULL_PTR);
    cstring_init(CNETCARD_IPV4STR(cnetcard), NULL_PTR);
    cstring_init(CNETCARD_MACSTR(cnetcard), NULL_PTR);
    BSET(CNETCARD_MACADDR(cnetcard), 0, 6);
    CNETCARD_IPV4VAL(cnetcard) = 0;
    CNETCARD_STATE(cnetcard)   = CNETCARD_ERR_STATE;
    return (0);
}

UINT32 cnetcard_clean(CNETCARD *cnetcard)
{
    cstring_clean(CNETCARD_NAME(cnetcard));
    cstring_clean(CNETCARD_IPV4STR(cnetcard));
    cstring_clean(CNETCARD_MACSTR(cnetcard));
    BSET(CNETCARD_MACADDR(cnetcard), 0, 6);
    CNETCARD_IPV4VAL(cnetcard) = 0;
    CNETCARD_STATE(cnetcard)   = CNETCARD_ERR_STATE;

    return (0);
}

UINT32 cnetcard_free(CNETCARD *cnetcard)
{
    cnetcard_clean(cnetcard);
    SAFE_FREE(cnetcard, LOC_CDEVICE_0002);
    return (0);
}

EC_BOOL cnetcard_cmp_name(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd)
{
    if(EC_FALSE == cstring_is_equal(CNETCARD_NAME(cnetcard_1st), CNETCARD_NAME(cnetcard_2nd)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_cmp_ipv4str(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd)
{
    if(EC_FALSE == cstring_is_equal(CNETCARD_IPV4STR(cnetcard_1st), CNETCARD_IPV4STR(cnetcard_2nd)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_cmp_ipv4val(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd)
{
    if(CNETCARD_IPV4VAL(cnetcard_1st) != CNETCARD_IPV4VAL(cnetcard_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_cmp_macstr(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd)
{
    if(EC_FALSE == cstring_is_equal(CNETCARD_MACSTR(cnetcard_1st), CNETCARD_MACSTR(cnetcard_2nd)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_cmp_state(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd)
{
    if(CNETCARD_STATE(cnetcard_1st) != CNETCARD_STATE(cnetcard_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_cmp(const CNETCARD *cnetcard_1st, const CNETCARD *cnetcard_2nd)
{
    if(EC_FALSE == cstring_is_equal(CNETCARD_NAME(cnetcard_1st), CNETCARD_NAME(cnetcard_2nd)))
    {
        return (EC_FALSE);
    }
    if(EC_FALSE == cstring_is_equal(CNETCARD_IPV4STR(cnetcard_1st), CNETCARD_IPV4STR(cnetcard_2nd)))
    {
        return (EC_FALSE);
    }
    if(EC_FALSE == cstring_is_equal(CNETCARD_MACSTR(cnetcard_1st), CNETCARD_MACSTR(cnetcard_2nd)))
    {
        return (EC_FALSE);
    }

    if(CNETCARD_IPV4VAL(cnetcard_1st) != CNETCARD_IPV4VAL(cnetcard_2nd))
    {
        return (EC_FALSE);
    }
    if(CNETCARD_STATE(cnetcard_1st) != CNETCARD_STATE(cnetcard_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_match_name(const CNETCARD *cnetcard_1st, const CSTRING *name)
{
    if(EC_FALSE == cstring_is_equal(CNETCARD_NAME(cnetcard_1st), name))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_match_ipv4str(const CNETCARD *cnetcard_1st, const CSTRING *ipv4str)
{
    if(EC_FALSE == cstring_is_equal(CNETCARD_IPV4STR(cnetcard_1st), ipv4str))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_match_ipv4val(const CNETCARD *cnetcard_1st, const UINT32 ipv4val)
{
    if(CNETCARD_IPV4VAL(cnetcard_1st) != ipv4val)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cnetcard_match_macaddr(const CNETCARD *cnetcard_1st, const UINT8 *macaddr)
{
    if(EC_FALSE == BCMP(CNETCARD_MACADDR(cnetcard_1st), macaddr, 6))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void cnetcard_print(LOG *log, const CNETCARD *cnetcard)
{
    sys_log(log, "device name    : %s\n", (char *)cstring_get_str(CNETCARD_NAME(cnetcard)));
    sys_log(log, "device ip  addr: %s (%lx)\n", (char *)cstring_get_str(CNETCARD_IPV4STR(cnetcard)), CNETCARD_IPV4VAL(cnetcard));
    sys_log(log, "device mac addr: %s\n", (char *)cstring_get_str(CNETCARD_MACSTR(cnetcard)));

    if(CNETCARD_UP_STATE == CNETCARD_STATE(cnetcard))
    {
        sys_log(log, "device state   : UP\n");
    }
    else if (CNETCARD_DOWN_STATE == CNETCARD_STATE(cnetcard))
    {
        sys_log(log, "device state   : DOWN\n");
    }
    else
    {
        sys_log(log, "device state   : UNKNOWN\n");
    }
}

UINT32 cnetcard_collect(CSET *cnetcard_set, const UINT32 max_cnetcard_num)
{
    int fd;
    struct ifreq *ifreq_tbl;
    struct ifconf ifc;
    struct sockaddr_in *in;
    UINT32 cnetcard_pos;
    UINT32 cnetcard_num;

    fd = csocket_open(AF_INET, SOCK_DGRAM, 0);
    if(0 > fd)
    {
        dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to create a socket\n");
        return ((UINT32)-1);
    }

    ifreq_tbl = (struct ifreq *)SAFE_MALLOC(sizeof(struct ifreq) * max_cnetcard_num, LOC_CDEVICE_0003);
    if(NULL_PTR == ifreq_tbl)
    {
        dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to malloc %ld struct ifreq\n", max_cnetcard_num);
        csocket_close(fd);
        return ((UINT32)-1);
    }

    ifc.ifc_len = sizeof(struct ifreq) * max_cnetcard_num;
    ifc.ifc_buf = (caddr_t) ifreq_tbl;

    if (0 != ioctl(fd, SIOCGIFCONF, (char *) &ifc))
    {
        dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to fetch %ld IF CONFIG\n", max_cnetcard_num);
        csocket_close(fd);
        SAFE_FREE(ifreq_tbl, LOC_CDEVICE_0004);
        return ((UINT32)-1);
    }

    cnetcard_num = ifc.ifc_len / sizeof(struct ifreq);/*actual device number*/
    //dbg_log(SEC_0011_CDEVICE, 5)(LOGSTDOUT, "cnetcard_num = %ld\n", cnetcard_num);

    for(cnetcard_pos = 0; cnetcard_pos < cnetcard_num; cnetcard_pos ++)
    {
        CNETCARD *cnetcard;
        struct ifreq *ifreq_item;

        ifreq_item = (ifreq_tbl + cnetcard_pos);
        //dbg_log(SEC_0011_CDEVICE, 5)(LOGSTDOUT, "ifreq_tbl %lx, cnetcard_pos %lx => ifreq_item %lx\n", ifreq_tbl, cnetcard_pos, ifreq_item);

        cnetcard = cnetcard_new();
        if(NULL_PTR == cnetcard)
        {
            dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to new CNETCARD when handle # %ld device\n", cnetcard_pos);
            csocket_close(fd);
            SAFE_FREE(ifreq_tbl, LOC_CDEVICE_0005);
            return ((UINT32)-1);
        }

        /*get device name*/
        cstring_format(CNETCARD_NAME(cnetcard), "%s", ifreq_item->ifr_name);

        /*judge whether the net card status is up */
        if(0 != ioctl(fd, SIOCGIFFLAGS, (char *)ifreq_item))
        {
            dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to fetch # %ld device IF FLAGS\n", cnetcard_pos);
            cnetcard_free(cnetcard);
            continue;
        }
        if(ifreq_item->ifr_flags & IFF_UP)
        {
            CNETCARD_STATE(cnetcard) = CNETCARD_UP_STATE;
        }
        else
        {
            CNETCARD_STATE(cnetcard) = CNETCARD_DOWN_STATE;
        }

        /*get IP of the net card */
        if (0 != ioctl(fd, SIOCGIFADDR, (char *)ifreq_item))
        {
            dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to fetch # %ld device IF ADDR\n", cnetcard_pos);
            cnetcard_free(cnetcard);
            continue;
        }

        in = (struct sockaddr_in*) (&(ifreq_item->ifr_addr));
        cstring_format(CNETCARD_IPV4STR(cnetcard), "%s", c_inet_ntos(&(in->sin_addr)));
        CNETCARD_IPV4VAL(cnetcard) = c_ipv4_to_word((char *)cstring_get_str(CNETCARD_IPV4STR(cnetcard)));

        /*get HW ADDRESS of the net card */
        if(0 != ioctl(fd, SIOCGIFHWADDR, (char *)ifreq_item))
        {
            dbg_log(SEC_0011_CDEVICE, 0)(LOGSTDOUT, "error:cnetcard_collect: failed to fetch # %ld device IF HW ADDR\n", cnetcard_pos);
            cnetcard_free(cnetcard);
            continue;
        }
        BCOPY(ifreq_item->ifr_hwaddr.sa_data, CNETCARD_MACADDR(cnetcard), 6);
        cstring_format(CNETCARD_MACSTR(cnetcard), "%02x:%02x:%02x:%02x:%02x:%02x",
                            (UINT8) ifreq_item->ifr_hwaddr.sa_data[0],
                            (UINT8) ifreq_item->ifr_hwaddr.sa_data[1],
                            (UINT8) ifreq_item->ifr_hwaddr.sa_data[2],
                            (UINT8) ifreq_item->ifr_hwaddr.sa_data[3],
                            (UINT8) ifreq_item->ifr_hwaddr.sa_data[4],
                            (UINT8) ifreq_item->ifr_hwaddr.sa_data[5]
                        );
        /*add to set*/
        if(EC_FALSE == cset_add(cnetcard_set, (void *)cnetcard, (CSET_DATA_CMP)cnetcard_cmp))
        {
            cnetcard_free(cnetcard);
        }
    }

    csocket_close(fd);
    SAFE_FREE(ifreq_tbl, LOC_CDEVICE_0006);

    //dbg_log(SEC_0011_CDEVICE, 3)(LOGSTDOUT, "info:cnetcard_collect: device list:\n");
    //cset_print(LOGSTDOUT, cnetcard_set, (CSET_DATA_PRINT)cnetcard_print);

    return (0);
}

EC_BOOL cnetcard_has_name(const CSET *cnetcard_set, const CSTRING *name)
{
    CNETCARD cnetcard;

    cnetcard_init(&cnetcard);
    cstring_clone(name, CNETCARD_NAME(&cnetcard));

    if(NULL_PTR == cset_search(cnetcard_set, (void *)&cnetcard, (CSET_DATA_CMP)cnetcard_cmp_name))
    {
        cnetcard_clean(&cnetcard);
        return (EC_FALSE);
    }
    cnetcard_clean(&cnetcard);
    return (EC_TRUE);
}

EC_BOOL cnetcard_has_ipv4str(const CSET *cnetcard_set, const CSTRING *ipv4str)
{
    CNETCARD cnetcard;

    cnetcard_init(&cnetcard);
    cstring_clone(ipv4str, CNETCARD_IPV4STR(&cnetcard));

    if(NULL_PTR == cset_search(cnetcard_set, (void *)&cnetcard, (CSET_DATA_CMP)cnetcard_cmp_ipv4str))
    {
        cnetcard_clean(&cnetcard);
        return (EC_FALSE);
    }
    cnetcard_clean(&cnetcard);
    return (EC_TRUE);
}

EC_BOOL cnetcard_has_ipv4val(const CSET *cnetcard_set, const UINT32 ipv4val)
{
    CNETCARD cnetcard;

    cnetcard_init(&cnetcard);
    CNETCARD_IPV4VAL(&cnetcard) = ipv4val;

    if(NULL_PTR == cset_search(cnetcard_set, (void *)&cnetcard, (CSET_DATA_CMP)cnetcard_cmp_ipv4val))
    {
        cnetcard_clean(&cnetcard);
        return (EC_FALSE);
    }
    cnetcard_clean(&cnetcard);
    return (EC_TRUE);
}

EC_BOOL cnetcard_has_macstr(const CSET *cnetcard_set, const CSTRING *macstr)
{
    CNETCARD cnetcard;

    cnetcard_init(&cnetcard);
    cstring_clone(macstr, CNETCARD_MACSTR(&cnetcard));

    if(NULL_PTR == cset_search(cnetcard_set, (void *)&cnetcard, (CSET_DATA_CMP)cnetcard_cmp_macstr))
    {
        cnetcard_clean(&cnetcard);
        return (EC_FALSE);
    }
    cnetcard_clean(&cnetcard);
    return (EC_TRUE);
}

EC_BOOL cnetcard_has_state(const CSET *cnetcard_set, const UINT32 state)
{
    CNETCARD cnetcard;

    cnetcard_init(&cnetcard);
    CNETCARD_STATE(&cnetcard) = state;

    if(NULL_PTR == cset_search(cnetcard_set, (void *)&cnetcard, (CSET_DATA_CMP)cnetcard_cmp_state))
    {
        cnetcard_clean(&cnetcard);
        return (EC_FALSE);
    }
    cnetcard_clean(&cnetcard);
    return (EC_TRUE);
}

CNETCARD * cnetcard_search_by_name(const CSET *cnetcard_set, const CSTRING *name)
{
    return (CNETCARD *)cset_search(cnetcard_set, (void *)name, (CSET_DATA_CMP)cnetcard_match_name);
}

CNETCARD * cnetcard_search_by_ipv4val(const CSET *cnetcard_set, const UINT32 ipv4val)
{
    return (CNETCARD *)cset_search(cnetcard_set, (void *)ipv4val, (CSET_DATA_CMP)cnetcard_match_ipv4val);
}

CNETCARD * cnetcard_search_by_ipv4str(const CSET *cnetcard_set, const CSTRING *ipv4str)
{
    return (CNETCARD *)cset_search(cnetcard_set, (void *)ipv4str, (CSET_DATA_CMP)cnetcard_match_ipv4str);
}

CNETCARD * cnetcard_search_by_macaddr(const CSET *cnetcard_set, const UINT8 *macaddr)
{
    return (CNETCARD *)cset_search(cnetcard_set, (void *)macaddr, (CSET_DATA_CMP)cnetcard_match_macaddr);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

