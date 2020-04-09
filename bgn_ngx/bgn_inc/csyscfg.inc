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

#ifndef _CSYSCFG_INC
#define _CSYSCFG_INC

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "cmap.h"
#include "taskcfg.h"

#define MODEL_TYPE_MASTER_SLAVE              ((UINT32) 1)/*master slave model*/
#define MODEL_TYPE_CROSS_CONNEC              ((UINT32) 2)/*cross connection model*/
#define MODEL_TYPE_ANY                       ((UINT32)-2)/*any   connection model*/
#define MODEL_TYPE_ERROR                     ((UINT32)-1)/*error connection model*/

/*cluster node*/
typedef struct
{
    CSTRING     role;
    CMAP        extras;
/*
    CSTRING     group;
    CSTRING     npdir;
    CSTRING     dndir;
*/
    UINT32      tcid;
    CVECTOR     rank_vec;/*item is rank (UINT32)*/
}CLUSTER_NODE_CFG;
#define CLUSTER_NODE_CFG_ROLE(cluster_node_cfg)                   (&((cluster_node_cfg)->role))
#define CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg)               (cstring_get_str(CLUSTER_NODE_CFG_ROLE(cluster_node_cfg)))
#define CLUSTER_NODE_CFG_EXTRAS(cluster_node_cfg)                 (&((cluster_node_cfg)->extras))
#define CLUSTER_NODE_CFG_TCID(cluster_node_cfg)                   ((cluster_node_cfg)->tcid)
#define CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg)               (c_word_to_ipv4(CLUSTER_NODE_CFG_TCID(cluster_node_cfg)))
#define CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg)               (&((cluster_node_cfg)->rank_vec))

#define CLUSTER_NODE_CFG_GROUP(this_cluster_node_cfg)             (cluster_node_cfg_get_extra_val_by_key_str(this_cluster_node_cfg, (const char *)"group"))
#define CLUSTER_NODE_CFG_GROUP_STR(this_cluster_node_cfg)         (cstring_get_str(CLUSTER_NODE_CFG_GROUP(this_cluster_node_cfg)))
#define CLUSTER_NODE_CFG_NPDIR(this_cluster_node_cfg)             (cluster_node_cfg_get_extra_val_by_key_str(this_cluster_node_cfg, (const char *)"npdir"))
#define CLUSTER_NODE_CFG_NPDIR_STR(this_cluster_node_cfg)         (cstring_get_str(CLUSTER_NODE_CFG_NPDIR(this_cluster_node_cfg)))
#define CLUSTER_NODE_CFG_DNDIR(this_cluster_node_cfg)             (cluster_node_cfg_get_extra_val_by_key_str(this_cluster_node_cfg, (const char *)"dndir"))
#define CLUSTER_NODE_CFG_DNDIR_STR(this_cluster_node_cfg)         (cstring_get_str(CLUSTER_NODE_CFG_DNDIR(this_cluster_node_cfg)))


#define CLUSTER_ID_ERROR    ((UINT32)-1)
/*
typedef struct
{
    CSTRING     key;
    CSTRING     val;
}CLUSTER_EXTRA;
*/
typedef struct
{
    UINT32     id;    /*unique cluster id       */
    CSTRING    name;  /*cluster alias name      */
    UINT32     model; /*cluster model           */
    CMAP       extras;/*key and val are CSTRING */
    CVECTOR    nodes; /*item is CLUSTER_NODE_CFG*/
}CLUSTER_CFG;
#define CLUSTER_CFG_ID(cluster_cfg)          ((cluster_cfg)->id)
#define CLUSTER_CFG_NAME(cluster_cfg)        (&((cluster_cfg)->name))
#define CLUSTER_CFG_NAME_STR(cluster_cfg)    (cstring_get_str(CLUSTER_CFG_NAME(cluster_cfg)))
#define CLUSTER_CFG_MODEL(cluster_cfg)       ((cluster_cfg)->model)
#define CLUSTER_CFG_EXTRAS(cluster_cfg)      (&((cluster_cfg)->extras))
#define CLUSTER_CFG_NODES(cluster_cfg)       (&((cluster_cfg)->nodes))

#define MCAST_TYPE_IS_MASTER             ((UINT32) 1)
#define MCAST_TYPE_IS_SLAVE              ((UINT32) 2)
#define MCAST_TYPE_IS_ERR                ((UINT32)-1)

#define MCAST_SRV_WILL_AUTO_BOOTUP       ((UINT32) 0)
#define MCAST_SRV_NOT_AUTO_BOOTUP        ((UINT32) 1)

#define MCAST_SRV_DEFAULT_INTERVAL       ((UINT32)15)/*default is 15 seconds*/

typedef struct
{
    UINT32      type;
    UINT32      tcid;

    UINT32      ipaddr;   /*udp mcast ipaddr*/
    UINT32      port;     /*udp mcast port*/
    UINT32      expire;   /*mcast expire interval, in seconds*/
    UINT32      timeout;  /*mcast timeout interval, in seconds*/
    UINT32      auto_flag;/*whether udp server bootup automatically*/
}MCAST_CFG;
#define MCAST_CFG_TYPE(mcast_cfg)         ((mcast_cfg)->type)
#define MCAST_CFG_TCID(mcast_cfg)         ((mcast_cfg)->tcid)
#define MCAST_CFG_TCID_STR(mcast_cfg)     (c_word_to_ipv4(MCAST_CFG_TCID(mcast_cfg)))
#define MCAST_CFG_IPADDR(mcast_cfg)       ((mcast_cfg)->ipaddr)
#define MCAST_CFG_IPADDR_STR(mcast_cfg)   (c_word_to_ipv4(MCAST_CFG_IPADDR(mcast_cfg)))
#define MCAST_CFG_PORT(mcast_cfg)         ((mcast_cfg)->port)
#define MCAST_CFG_EXPIRE(mcast_cfg)       ((mcast_cfg)->expire)
#define MCAST_CFG_TIMEOUT(mcast_cfg)      ((mcast_cfg)->timeout)
#define MCAST_CFG_AUTO_FLAG(mcast_cfg)    ((mcast_cfg)->auto_flag)


/*self-discovery of service over udp mcast*/
typedef struct
{
    CSTRING     netcard;        /*[optional] nic name*/
    UINT32      ipaddr;         /*udp mcast ipaddr*/
    UINT32      port;           /*udp mcast port*/
    UINT32      switch_flag;    /*on|off, default is off*/
}SDISC_CFG;

#define SDISC_CFG_NETCARD(sdisc_cfg)      (&((sdisc_cfg)->netcard))
#define SDISC_CFG_NETCARD_STR(sdisc_cfg)  (cstring_get_str(SDISC_CFG_NETCARD(sdisc_cfg)))
#define SDISC_CFG_IPADDR(sdisc_cfg)       ((sdisc_cfg)->ipaddr)
#define SDISC_CFG_IPADDR_STR(sdisc_cfg)   (c_word_to_ipv4(SDISC_CFG_IPADDR(sdisc_cfg)))
#define SDISC_CFG_PORT(sdisc_cfg)         ((sdisc_cfg)->port)
#define SDISC_CFG_SWITCH(sdisc_cfg)       ((sdisc_cfg)->switch_flag)

#define BCAST_DHCP_TYPE_IS_MASTER             ((UINT32) 1)
#define BCAST_DHCP_TYPE_IS_SLAVE              ((UINT32) 2)
#define BCAST_DHCP_TYPE_IS_ERR                ((UINT32)-1)

#define BCAST_DHCP_SRV_WILL_AUTO_BOOTUP       ((UINT32) 0)
#define BCAST_DHCP_SRV_NOT_AUTO_BOOTUP        ((UINT32) 1)

#define BCAST_DHCP_SRV_DEFAULT_INTERVAL       ((UINT32)15)/*default is 15 seconds*/

typedef struct
{
    UINT32      type;
    UINT32      tcid;
    CSTRING     netcard;
    UINT32      subnet;   /*udp bcast ipaddr*/
    UINT32      mask;     /*udp bcast mask*/
    UINT32      auto_flag;/*whether udp server bootup automatically*/
}BCAST_DHCP_CFG;
#define BCAST_DHCP_CFG_TYPE(bcast_dhcp_cfg)         ((bcast_dhcp_cfg)->type)
#define BCAST_DHCP_CFG_TCID(bcast_dhcp_cfg)         ((bcast_dhcp_cfg)->tcid)
#define BCAST_DHCP_CFG_TCID_STR(bcast_dhcp_cfg)     (c_word_to_ipv4(BCAST_DHCP_CFG_TCID(bcast_dhcp_cfg)))
#define BCAST_DHCP_NETCARD(bcast_dhcp_cfg)          (&((bcast_dhcp_cfg)->netcard))
#define BCAST_DHCP_NETCARD_STR(bcast_dhcp_cfg)      (cstring_get_str(BCAST_DHCP_NETCARD(bcast_dhcp_cfg)))
#define BCAST_DHCP_CFG_SUBNET(bcast_dhcp_cfg)       ((bcast_dhcp_cfg)->subnet)
#define BCAST_DHCP_CFG_SUBNET_STR(bcast_dhcp_cfg)   (c_word_to_ipv4(BCAST_DHCP_CFG_SUBNET(bcast_dhcp_cfg)))
#define BCAST_DHCP_CFG_MASK(bcast_dhcp_cfg)         ((bcast_dhcp_cfg)->mask)
#define BCAST_DHCP_CFG_MASK_STR(bcast_dhcp_cfg)     (c_word_to_ipv4(BCAST_DHCP_CFG_MASK(bcast_dhcp_cfg)))
#define BCAST_DHCP_CFG_AUTO_FLAG(bcast_dhcp_cfg)    ((bcast_dhcp_cfg)->auto_flag)

/*bind or map MAC addr and IPv4 addr*/
typedef struct
{
    UINT8     mac_addr[6];
    UINT8     rsvd1[2];
    UINT32    ipv4_addr;    /*in host byte order*/
}MACIP_CFG;
#define MACIP_CFG_MAC_SIZE                  (6)
#define MACIP_CFG_MAC_ADDR(macip_cfg)       ((macip_cfg)->mac_addr)
#define MACIP_CFG_MAC_ADDR_STR(macip_cfg)   (mac_addr_to_str(MACIP_CFG_MAC_ADDR(macip_cfg)))
#define MACIP_CFG_IPV4_ADDR(macip_cfg)      ((macip_cfg)->ipv4_addr)
#define MACIP_CFG_IPV4_ADDR_STR(macip_cfg)  (c_word_to_ipv4(MACIP_CFG_IPV4_ADDR(macip_cfg)))

typedef struct
{
    TASK_CFG        task_cfg;
    CVECTOR         cluster_vec;        /*item is CLUSTER_CFG*/
    CVECTOR         macip_cfg_vec;      /*item is MACIP_CFG*/
    CVECTOR         paras_cfg;
    MCAST_CFG       mcast_cfg;
    SDISC_CFG       sdisc_cfg;/*self-discovery of service over udp mcast*/
    BCAST_DHCP_CFG  bcast_dhcp_cfg;
}SYS_CFG;

#define SYS_CFG_TASK_CFG(sys_cfg)            (&((sys_cfg)->task_cfg))
#define SYS_CFG_CLUSTER_VEC(sys_cfg)         (&((sys_cfg)->cluster_vec))
#define SYS_CFG_MACIP_CFG_VEC(sys_cfg)       (&((sys_cfg)->macip_cfg_vec))
#define SYS_CFG_PARAS_CFG(sys_cfg)           (&((sys_cfg)->paras_cfg))
#define SYS_CFG_MCAST_CFG(sys_cfg)           (&((sys_cfg)->mcast_cfg))
#define SYS_CFG_SDISC_CFG(sys_cfg)           (&((sys_cfg)->sdisc_cfg))
#define SYS_CFG_BCAST_DHCP_CFG(sys_cfg)      (&((sys_cfg)->bcast_dhcp_cfg))

#endif/*_CSYSCFG_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

