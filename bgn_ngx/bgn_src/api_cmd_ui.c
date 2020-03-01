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

#include "type.h"

#include "clist.h"
#include "cvector.h"
#include "cstring.h"

#include "mm.h"

#include "cmisc.h"
#include "task.inc"
#include "task.h"
#include "tcnode.h"
#include "ctimer.h"

#include "taskcfg.inc"
#include "taskcfg.h"
#include "taskcfgchk.h"
#include "cxml.h"

#include "crfs.h"
#include "crfsnp.h"
#include "crfsdn.h"
#include "crfsc.h"

#include "cxfs.h"
#include "cxfsnp.h"
#include "cxfsdn.h"

#include "chfs.h"
#include "chfsnp.h"

#include "csfs.h"

#include "ctdns.h"
#include "cdetect.h"

#include "csession.h"
#include "cbytes.h"

#include "log.h"
#include "chashalgo.h"

#include "cparacfg.h"

#include "findex.inc"

#include "cconsole.h"
#include "ctdns.h"
#include "cp2p.h"

#include "api_cmd.inc"
#include "api_cmd.h"
#include "api_cmd_ui.h"
#include "api_ui_util.h"

static char     api_cmd_line_buff[ API_CMD_LINE_BUFF_SIZE ];
static uint32_t api_cmd_line_buff_size = sizeof(api_cmd_line_buff) / sizeof(api_cmd_line_buff[0]);

static const char *api_cmd_prompt = "bgn> ";
static CCOND      *api_cmd_ccond  = NULL_PTR;

EC_BOOL api_cmd_ui_init(CMD_ELEM_VEC *cmd_elem_vec, CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec)
{
    CMD_ELEM *where    = NULL_PTR;
    CMD_ELEM *tcid     = NULL_PTR;
    CMD_ELEM *rank     = NULL_PTR;
    CMD_ELEM *times    = NULL_PTR;
    CMD_ELEM *maski    = NULL_PTR;
    CMD_ELEM *maske    = NULL_PTR;
    CMD_ELEM *maskr    = NULL_PTR;
    CMD_ELEM *ipaddr   = NULL_PTR;
    CMD_ELEM *hops     = NULL_PTR;
    CMD_ELEM *remotes  = NULL_PTR;
    CMD_ELEM *ttl      = NULL_PTR;
    CMD_ELEM *on_off   = NULL_PTR;
    CMD_ELEM *cmd      = NULL_PTR;
    CMD_ELEM *oid      = NULL_PTR;

    where  = api_cmd_elem_create_cstring("<console|log>");
    api_cmd_elem_vec_add(cmd_elem_vec, where);

    tcid   = api_cmd_elem_create_tcid("<tcid>");
    api_cmd_elem_vec_add(cmd_elem_vec, tcid);

    rank   = api_cmd_elem_create_uint32("<rank>");
    api_cmd_elem_vec_add(cmd_elem_vec, rank);

    times  = api_cmd_elem_create_uint32("<times>");
    api_cmd_elem_vec_add(cmd_elem_vec, times);

    maski  = api_cmd_elem_create_mask("<maski>");
    api_cmd_elem_vec_add(cmd_elem_vec, maski);

    maske  = api_cmd_elem_create_mask("<maske>");
    api_cmd_elem_vec_add(cmd_elem_vec, maske);

    maskr  = api_cmd_elem_create_mask("<maskr>");
    api_cmd_elem_vec_add(cmd_elem_vec, maskr);

    ipaddr  = api_cmd_elem_create_ipaddr("<ipaddr>");
    api_cmd_elem_vec_add(cmd_elem_vec, ipaddr);

    hops  = api_cmd_elem_create_uint32("<max hops>");
    api_cmd_elem_vec_add(cmd_elem_vec, hops);

    ttl  = api_cmd_elem_create_uint32("<time to live in seconds>");
    api_cmd_elem_vec_add(cmd_elem_vec, ttl);

    remotes  = api_cmd_elem_create_uint32("<max remotes>");
    api_cmd_elem_vec_add(cmd_elem_vec, remotes);

    on_off = api_cmd_elem_create_list("<on|off>");
    api_cmd_elem_create_list_item(on_off, "on" , SWITCH_ON);
    api_cmd_elem_create_list_item(on_off, "off", SWITCH_OFF);
    api_cmd_elem_vec_add(cmd_elem_vec, on_off);

    cmd  = api_cmd_elem_create_cstring("cmd>");
    api_cmd_elem_vec_add(cmd_elem_vec, cmd);

    oid  = api_cmd_elem_create_uint32("<oid>");
    api_cmd_elem_vec_add(cmd_elem_vec, oid);

    api_cmd_help_vec_create(cmd_help_vec, "help"         , "help");
    //api_cmd_help_vec_create(cmd_help_vec, "version"      , "show version on {all | tcid <tcid>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "run script"   , "script <file name>");

    api_cmd_help_vec_create(cmd_help_vec, "dns resolve"   , "dns resolve <domain> from <server> on tcid <tcid> rank <rank> at <console|log>");

    api_cmd_help_vec_create(cmd_help_vec, "act sysconfig" , "act sysconfig on {all | tcid <tcid> rank <rank>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "show sysconfig", "show sysconfig on {all | tcid <tcid> rank <rank>} at <console|log>");

    //api_cmd_help_vec_create(cmd_help_vec, "add route"    , "add route des_tcid <tcid> maskr <maskr> next_tcid <tcid> on tcid <tcid>");
    //api_cmd_help_vec_create(cmd_help_vec, "del route"    , "del route des_tcid <tcid> maskr <maskr> next_tcid <tcid> on tcid <tcid>");

    //api_cmd_help_vec_create(cmd_help_vec, "add conn"    , "add <num> conn to tcid <tcid> ipaddr <ipaddr> port <port> on {all | tcid <tcid>}");

    api_cmd_help_vec_create(cmd_help_vec, "diag mem"     , "diag mem {all | type <type>} on {all | tcid <tcid> rank <rank>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "diag socket"  , "diag socket on {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "breathing mem", "breathing mem on {all | tcid <tcid> rank <rank>}");
    //api_cmd_help_vec_create(cmd_help_vec, "mon oid"      , "mon oid <oid> for <times> times on {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "show client"  , "show client {all | tcid <tcid>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "show mem"     , "show mem {all | type <type>} on {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "show queue"   , "show queue on {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "check slowndown"   , "check slow down on {all | tcid <tcid> rank <rank>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "show thread"  , "show thread {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "show route"   , "show route {all | tcid <tcid>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "show taskcomm", "show taskcomm {all | tcid <tcid>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "show load"    , "show rank load on {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "sync load"    , "sync rank load from tcid <tcid> rank <rank> to {all | tcid <tcid> rank <rank>}");
    //api_cmd_help_vec_create(cmd_help_vec, "set  load"    , "set rank load of tcid <tcid> rank <rank> as load que <load> obj <load> cpu <load> mem <load> dsk <load> net <load> on {all | tcid <tcid> rank <rank>}");

    //api_cmd_help_vec_create(cmd_help_vec, "vendor show"   , "show vendor on {all | tcid <tcid>} at <console|log>");

    //api_cmd_help_vec_create(cmd_help_vec, "enable  brd"  , "enable task brd on {all | tcid <tcid> rank <rank>}");
    //api_cmd_help_vec_create(cmd_help_vec, "disable brd"  , "disable task brd on {all | tcid <tcid> rank <rank>}");

    //api_cmd_help_vec_create(cmd_help_vec, "shell"        , "shell <cmd> on {all | tcid <tcid>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "switch"       , "switch {all | tcid <tcid> rank <rank>} log <on|off>");
    //api_cmd_help_vec_create(cmd_help_vec, "switch"       , "switch ngx memc on {all | tcid <tcid> rank <rank>} to <on|off>");
    api_cmd_help_vec_create(cmd_help_vec, "shutdown"     , "shutdown <dbg | mon | work> {all | tcid <tcid>}");
    //api_cmd_help_vec_create(cmd_help_vec, "ping taskcomm", "ping taskcomm tcid <tcid> at <console|log>");

    //api_cmd_help_vec_create(cmd_help_vec, "sync taskcomm", "sync taskcomm hops <max hops> remotes <max remotes> ttl <time to live in seconds> on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "taskcfgchk net"    , "taskcfgchk net {all | tcid <tcid>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "taskcfgchk route"  , "taskcfgchk route tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "taskcfgchk tracert", "taskcfgchk tracert src_tcid <tcid> des_tcid <tcid> hops <max hops> at <console|log>");

#if 1
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs create"  , "hsrfs <id> create np model <model> max num <np mum> with hash algo <id> and root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs create"  , "hsrfs <id> create dn with root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs add"     , "hsrfs <id> add disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs del"     , "hsrfs <id> del disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs mount"   , "hsrfs <id> mount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs umount"  , "hsrfs <id> umount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs open"    , "hsrfs <id> open from root <dir> on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs close"   , "hsrfs <id> close on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs read"    , "hsrfs <id> read file <name> on tcid <tcid> at <console|log>");

    api_cmd_help_vec_create(cmd_help_vec, "hsrfs write"   , "hsrfs <id> write file <name> with content <string> on tcid <tcid> at <console|log>");

    api_cmd_help_vec_create(cmd_help_vec, "hsrfs delete"  , "hsrfs <id> delete {file|dir|path} <name> on tcid <tcid> at <console|log>");

    /* for deleting root dir / only! */
    /* but do not exposure at api cmd ui */
    //api_cmd_help_vec_create(cmd_help_vec, "hsrfs delete root dir"  , "hsrfs <id> delete root dir / on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs recycle" , "hsrfs <id> recycle on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs retire"  , "hsrfs <id> retire max <num> files on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs flush"   , "hsrfs <id> flush on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs flush"   , "hsrfs <id> flush npp on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs flush"   , "hsrfs <id> flush dn on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs mkdir"   , "hsrfs <id> mkdir <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs search"  , "hsrfs <id> search <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs count"   , "hsrfs <id> count file num of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs count"   , "hsrfs <id> count file size of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs qfile"   , "hsrfs <id> qfile <file> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs qdir"    , "hsrfs <id> qdir <dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs qlist"   , "hsrfs <id> qlist <file or dir> {full | short | tree} [of np <np id>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs show"    , "hsrfs <id> show npp [<lru | del>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs show"    , "hsrfs <id> show dn on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs show"    , "hsrfs <id> show cached np [<lru | del>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs show"    , "hsrfs <id> show specific np <id> [<lru | del>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfs show"    , "hsrfs <id> show locked files on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hsrfs md5sum"  , "hsrfs <id> md5sum file <name> on tcid <tcid> at <console|log>");
#endif
#if 1
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs create"  , "hsxfs <id> create np model <model> max num <np mum> with hash algo <id> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs create"  , "hsxfs <id> create dn on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs create"  , "hsxfs <id> create sata bad bitmap on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs add"     , "hsxfs <id> add disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs del"     , "hsxfs <id> del disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs mount"   , "hsxfs <id> mount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs umount"  , "hsxfs <id> umount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs open"    , "hsxfs <id> open from sata <path> and ssd <path|none> on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs close"   , "hsxfs <id> close on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs read"    , "hsxfs <id> read file <name> on tcid <tcid> at <console|log>");

    api_cmd_help_vec_create(cmd_help_vec, "hsxfs write"   , "hsxfs <id> write file <name> with content <string> on tcid <tcid> at <console|log>");

    api_cmd_help_vec_create(cmd_help_vec, "hsxfs delete"  , "hsxfs <id> delete {file|dir|path} <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs set"     , "hsxfs <id> <set|unset|check> <sata|ssd> bad page <page no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs show"    , "hsxfs <id> show <sata|ssd> bad pages on tcid <tcid> at <console|log>");

    /* for deleting root dir / only! */
    /* but do not exposure at api cmd ui */
    //api_cmd_help_vec_create(cmd_help_vec, "hsxfs delete root dir"  , "hsxfs <id> delete root dir / on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs recycle" , "hsxfs <id> recycle on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs retire"  , "hsxfs <id> retire max <num> files on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs flush"   , "hsxfs <id> flush on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs flush"   , "hsxfs <id> flush npp on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs flush"   , "hsxfs <id> flush dn on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs set"     , "hsxfs <id> <set|unset|check> read only on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs sync"    , "hsxfs <id> sync on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs replay"  , "hsxfs <id> replay op on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs pop"     , "hsxfs <id> pop op <size> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs mkdir"   , "hsxfs <id> mkdir <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs search"  , "hsxfs <id> search <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs count"   , "hsxfs <id> count file num of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs count"   , "hsxfs <id> count file size of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs qfile"   , "hsxfs <id> qfile <file> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs qdir"    , "hsxfs <id> qdir <dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs qlist"   , "hsxfs <id> qlist <file or dir> {full | short | tree} [of np <np id>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs show"    , "hsxfs <id> show npp [<lru | del>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs show"    , "hsxfs <id> show dn on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs show"    , "hsxfs <id> show cached np [<lru | del>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs show"    , "hsxfs <id> show specific np <id> [<lru | del>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsxfs show"    , "hsxfs <id> show locked files on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hsxfs md5sum"  , "hsxfs <id> md5sum file <name> on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hsxfs md5sum"  , "hsxfs <id> md5sum bigfile <name> seg <no> on tcid <tcid> at <console|log>");
#endif


#if 0
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc open"    , "hsrfsc open from root <dir> on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc close"   , "hsrfsc close on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc read"    , "hsrfsc read file <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc write"   , "hsrfsc write file <name> with content <string> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc create"  , "hsrfsc create bigfile <name> with size <file size> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc read"    , "hsrfsc read bigfile <name> from offset <offset> max <max len> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc download", "hsrfsc download bigfile <name> to file <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc upload"  , "hsrfsc upload file <name> to bigfile <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc write"   , "hsrfsc write bigfile <name> with content <string> at offset <offset> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc delete"  , "hsrfsc delete bigfile <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc delete"  , "hsrfsc delete {file|dir|path} <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc recycle" , "hsrfsc recycle on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc search"  , "hsrfsc search {file|dir} <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc count"   , "hsrfsc count file size of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc qfile"   , "hsrfsc qfile <file> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc md5sum"  , "hsrfsc md5sum file <name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc md5sum"  , "hsrfsc md5sum bigfile <name> seg <no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc dir"     , "hsrfsc {add|del|has} dir <name> <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hsrfsc dt"      , "hsrfsc {flush|load|clone|rollback|show} dt on tcid <tcid> at <console|log>");

#endif
#if 0
    api_cmd_help_vec_create(cmd_help_vec, "hshfs create"  , "hshfs create np model <model> max num <np mum> with root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs create"  , "hshfs create dn with root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs add"     , "hshfs add disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs del"     , "hshfs del disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs mount"   , "hshfs mount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs umount"  , "hshfs umount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs open"    , "hshfs open from np root <dir> and dn root <dir> on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs close"   , "hshfs close on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs read"    , "hshfs read file <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs write"   , "hshfs write file <file name> with content <string> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs delete"  , "hshfs delete file <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs recycle" , "hshfs recycle on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs retire"  , "hshfs retire max <num> files created before <n> seconds on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs search"  , "hshfs search <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs qfile"   , "hshfs qfile <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs count"   , "hshfs count file num on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs count"   , "hshfs count file size of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs show"    , "hshfs show npp on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hshfs show"    , "hshfs show dn on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hshfs show"    , "hshfs show cached np on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hshfs show"    , "hshfs show specific np <id> on tcid <tcid> at <console|log>");
#endif

#if 0
    api_cmd_help_vec_create(cmd_help_vec, "hssfs create"  , "hssfs create np model <model> max num <np mum> with root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs create"  , "hssfs create dn with root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs add"     , "hssfs add disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs del"     , "hssfs del disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs mount"   , "hssfs mount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs umount"  , "hssfs umount disk <disk no> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs open"    , "hssfs open from np root <dir> and dn root <dir> on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs close"   , "hssfs close on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs read"    , "hssfs read file <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs write"   , "hssfs write file <file name> with content <string> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs delete"  , "hssfs delete file <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs search"  , "hssfs search <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs qfile"   , "hssfs qfile <file name> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs count"   , "hssfs count file num on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs count"   , "hssfs count file size of <path> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs show"    , "hssfs show npp on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "hssfs show"    , "hssfs show dn on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hssfs show"    , "hssfs show cached np on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "hssfs show"    , "hssfs show specific np <id> on tcid <tcid> at <console|log>");
#endif

#if 1
    api_cmd_help_vec_create(cmd_help_vec, "tdns create"  , "tdns create np model <model> max num <np mum> with root <root dir> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns start"   , "tdns start from root <dir> on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns end"     , "tdns end on tcid <tcid>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns config"  , "tdns config service <service> tcid <tcid> port <port> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns reserve" , "tdns reserve service <service> ip <ip> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns release" , "tdns release service <service> tcid <tcid> port <port> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns get"     , "tdns get tcid <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns get"     , "tdns get service <service> max nodes <num> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns set"     , "tdns set tcid <tcid> ip <ip> port <port> [service <service>] on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns delete"  , "tdns delete tcid <tcid> on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "tdns online"  , "tdns online service <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "tdns offline" , "tdns offline service <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns refresh" , "tdns refresh path <cache path> service <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns search"  , "tdns search tcid <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns count"   , "tdns count tcid num on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns count"   , "tdns count service <service > node num on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "tdns show"    , "tdns show <npp|svp> on tcid <tcid> at <console|log>");
#endif

#if 0
    api_cmd_help_vec_create(cmd_help_vec, "detect show"   , "detect show orig nodes on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "detect show"   , "detect show orig node <domain> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "detect dns"    , "detect dns resolve domain <domain>  on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "detect process", "detect process <num> tasks on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "detect process", "detect loop process <num> tasks on tcid <tcid> at <console|log>");
#endif

#if 1
    api_cmd_help_vec_create(cmd_help_vec, "p2p file"    , "p2p upload <src file> to <service> <des file> <on|to> tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p file"    , "p2p download <service> <src file> from <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p file"    , "p2p push <service> <src file> to {all | network <level> {all | tcid <tcid>}} on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p file"    , "p2p pull <service> <src file> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p file"    , "p2p flush <service> <src file> to <des file> in {all | network <level> {all | tcid <tcid>}} on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p file"    , "p2p delete <service> <src file> in {all | network <level> {all | tcid <tcid>}} on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p cmd"     , "p2p execute <service> <cmd> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p cmd"     , "p2p deliver <service> <cmd> in {all | network <level> {all | tcid <tcid>}} on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p online"  , "p2p online <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "p2p offline" , "p2p offline <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>");

#endif

#if 0
    api_cmd_help_vec_create(cmd_help_vec, "session add"   , "session add name <name> expire <nsec> on tcid <tcid> rank <rank> modi <modi> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "session rmv"   , "session rmv [name[regex] <name> | id[regex] <id>] on tcid <tcid> rank <rank> modi <modi> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "session set"   , "session set [name <name> | id <id>] key <key path> val <val> on tcid <tcid> rank <rank> modi <modi> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "session get"   , "session get [nameregex <name> | idregex <id>] key <key path> on tcid <tcid> rank <rank> modi <modi> at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "session show"  , "session show on tcid <tcid> rank <rank> modi <modi> at <console|log>");
#endif
    //api_cmd_help_vec_create(cmd_help_vec, "exec download" , "exec download <file> on {all|tcid <tcid>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "exec upload"   , "exec upload <file> with <content> on {all|tcid <tcid>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "exec shell"    , "exec shell <cmd> on {all|tcid <tcid>} at <console|log>");

    //api_cmd_help_vec_create(cmd_help_vec, "udp server"    , "{start|stop|status} udp server on tcid <tcid> at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "download file" , "download file <src fname> to <des fname> from tcid <tcid>  at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "upload   file" , "upload file <src fname> to <des fname> on tcid <tcid>  at <console|log>");

    api_cmd_help_vec_create(cmd_help_vec, "log rotate"    , "rotate log <0|5|8> on {all | tcid <tcid> rank <rank>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "log level"     , "show log level on {all | tcid <tcid> rank <rank>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "log level"     , "set log level table to <level> on {all | tcid <tcid> rank <rank>} at <console|log>");
    api_cmd_help_vec_create(cmd_help_vec, "log level"     , "set log level sector <sector id> to <level> on {all | tcid <tcid> rank <rank>} at <console|log>");
    //api_cmd_help_vec_create(cmd_help_vec, "say hello"     , "say hello [loop <num>] to tcid <tcid> rank <rank> on {all | tcid <tcid> rank <rank>} at <console|log>");

    /*----------------------------------------------------------------------------------------------------------------------------------------------------------------*/
    api_cmd_comm_define(cmd_tree, api_cmd_ui_add_route                   , "add route des_tcid %t maskr %m next_tcid %t on tcid %t", tcid, maskr, tcid, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_del_route                   , "del route des_tcid %t maskr %m next_tcid %t on tcid %t", tcid, maskr, tcid, tcid);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_add_conn                    , "add %n conn to tcid %t ipaddr %p port %n on tcid %t", rank, tcid, ipaddr, rank, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_add_conn_all                , "add %n conn to tcid %t ipaddr %p port %n on all"    , rank, tcid, ipaddr, rank);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_diag_mem_all                , "diag mem all on all at %s"                       , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_diag_mem                    , "diag mem all on tcid %t rank %n at %s"           , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_diag_csocket_cnode_all      , "diag socket on all at %s"                       , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_diag_csocket_cnode          , "diag socket on tcid %t rank %n at %s"           , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_diag_mem_all_of_type        , "diag mem type %n on all at %s"                   , rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_diag_mem_of_type            , "diag mem type %n on tcid %t rank %n at %s"       , rank, tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_breathing_mem               , "breathing mem on tcid %t rank %n"                , tcid, rank);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_breathing_mem_all           , "breathing mem on all");

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_client_all             , "show client all at %s"                           , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_client                 , "show client tcid %t at %s"                       , tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_dns_resolve_demo            , "dns resolve %s from %s on tcid %t rank %n at %s" , where, where, tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_activate_sys_cfg_all        , "act sysconfig on all at %s"                 , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_activate_sys_cfg            , "act sysconfig on tcid %t rank %n at %s"     , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_sys_cfg_all            , "show sysconfig on all at %s"                 , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_sys_cfg                , "show sysconfig on tcid %t rank %n at %s"     , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_mem_all                , "show mem all on all at %s"                       , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_mem                    , "show mem all on tcid %t rank %n at %s"           , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_mem_all_of_type        , "show mem type %n on all at %s"                   , rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_mem_of_type            , "show mem type %n on tcid %t rank %n at %s"       , rank, tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_queue_all              , "show queue on all at %s"                            , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_queue                  , "show queue on tcid %t rank %n at %s"                , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_check_slowdown_all          , "check slow down on all at %s"                    , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_check_slowdown              , "check slow down on tcid %t rank %n at %s"        , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_thread_all             , "show thread all at %s"                           , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_thread                 , "show thread tcid %t rank %n at %s"               , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_route_all              , "show route all at %s"                            , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_route                  , "show route tcid %t at %s"                        , tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_taskcomm_all           , "show taskcomm all at %s"                         , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_taskcomm               , "show taskcomm tcid %t at %s"                     , tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_version                , "show version on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_version_all            , "show version on all at %s", where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_vendor                 , "show vendor on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_vendor_all             , "show vendor on all at %s", where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_rank_load_all          , "show rank load on all at %s"                     , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_rank_load              , "show rank load on tcid %t rank %n at %s"         , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_run_shell_all               , "shell %s on all at %s"                           , cmd, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_run_shell                   , "shell %s on tcid %t at %s"                       , cmd, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_switch_log_all              , "switch all log %l"                               , on_off);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_switch_log                  , "switch tcid %t rank %n log %l"                   , tcid, rank, on_off);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_switch_ngx_memc_all         , "switch ngx memc on all to %l"                    , on_off);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_switch_ngx_memc             , "switch ngx memc on tcid %t rank %n to %l"        , tcid, rank, on_off);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_rotate_log_all              , "rotate log %n on all at %s"                     , rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_rotate_log                  , "rotate log %n on tcid %t rank %n at %s"         , rank, tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_do_test                     , "do test on tcid %t rank %n at %s"               , tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_shutdown_dbg_all            , "shutdown dbg all"                                );
    api_cmd_comm_define(cmd_tree, api_cmd_ui_shutdown_dbg                , "shutdown dbg tcid %t"                            , tcid);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_shutdown_work_all           , "shutdown work all"                               );
    api_cmd_comm_define(cmd_tree, api_cmd_ui_shutdown_work               , "shutdown work tcid %t"                           , tcid);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_shutdown_mon_all            , "shutdown mon all"                                );
    api_cmd_comm_define(cmd_tree, api_cmd_ui_shutdown_mon                , "shutdown mon tcid %t"                            , tcid);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_ping_taskcomm               , "ping taskcomm tcid %t at %s"                     , tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_sync_taskcomm_from_local    , "sync taskcomm hops %n remotes %n ttl %n on tcid %t at %s" , hops, remotes, ttl, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_sync_rank_load              , "sync rank load from tcid %t rank %n to tcid %t rank %n"   , tcid, rank, tcid, rank);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_sync_rank_load_to_all       , "sync rank load from tcid %t rank %n to all"   , tcid, rank);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_set_rank_load               , "set rank load of tcid %t rank %n as load que %n obj %n cpu %n mem %n dsk %n net %n on tcid %t rank %n"   , tcid, rank, rank, rank, rank, rank, rank, rank, tcid, rank);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_set_rank_load_on_all        , "set rank load of tcid %t rank %n as load %n on all"   , tcid, rank, rank);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_enable_task_brd             , "enable task brd on tcid %t rank %n", tcid, rank);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_enable_all_task_brd         , "enable task brd on all");

    api_cmd_comm_define(cmd_tree, api_cmd_ui_disable_task_brd            , "disable task brd on tcid %t rank %n", tcid, rank);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_disable_all_task_brd        , "disable task brd on all");

    api_cmd_comm_define(cmd_tree, api_cmd_ui_taskcfgchk_net_all          , "taskcfgchk net all at %s"                        , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_taskcfgchk_net              , "taskcfgchk net tcid %t at %s"                    , tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_taskcfgchk_route            , "taskcfgchk route tcid %t at %s"                  , tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_taskcfgchk_route_trace      , "taskcfgchk tracert src_tcid %t des_tcid %t hops %n at %s", tcid, tcid, hops, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_add          , "session add name %s expire %n on tcid %t rank %n modi %n at %s", where, rank, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_rmv_by_name  , "session rmv name %s on tcid %t rank %n modi %n at %s", where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_rmv_by_id    , "session rmv id %n on tcid %t rank %n modi %n at %s", rank, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_rmv_by_name_regex  , "session rmv nameregex %s on tcid %t rank %n modi %n at %s", where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_rmv_by_id_regex    , "session rmv idregex %s on tcid %t rank %n modi %n at %s", where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_set_by_name  , "session set name %s key %s val %s on tcid %t rank %n modi %n at %s", where, where, where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_set_by_id    , "session set id %n key %s val %s on tcid %t rank %n modi %n at %s", where, where, where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_get_by_name  , "session get name %s key %s on tcid %t rank %n modi %n at %s", where, where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_get_by_id    , "session get id %n key %s on tcid %t rank %n modi %n at %s", rank, where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_show         , "session show on tcid %t rank %n modi %n at %s", tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_get_by_name_regex  , "session get nameregex %s key %s on tcid %t rank %n modi %n at %s", where, where, tcid, rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csession_get_by_id_regex    , "session get idregex %s key %s on tcid %t rank %n modi %n at %s", where, where, tcid, rank, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_exec_download_all     , "exec download %s on all at %s"      , where, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_exec_download         , "exec download %s on tcid %t at %s"  , where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_exec_upload_all       , "exec upload %s with %s on all at %s"          , where, where, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_exec_upload           , "exec upload %s with %s on tcid %t at %s"      , where, where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_exec_shell_all        , "exec shell %s on all at %s"      , where, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_exec_shell            , "exec shell %s on tcid %t at %s"  , where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_start_mcast_udp_server, "start udp server on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_stop_mcast_udp_server , "stop udp server on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_status_mcast_udp_server , "status udp server on tcid %t at %s", tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_create_npp       , "hsrfs %n create np model %n max num %n with hash algo %n and root %s on tcid %t at %s", rank, rank, rank, rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_create_dn        , "hsrfs %n create dn with root %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_add_disk         , "hsrfs %n add disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_del_disk         , "hsrfs %n del disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_mount_disk       , "hsrfs %n mount disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_umount_disk      , "hsrfs %n umount disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_open             , "hsrfs %n open from root %s on tcid %t", rank, where, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_close            , "hsrfs %n close on tcid %t", rank, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_read             , "hsrfs %n read file %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_write            , "hsrfs %n write file %s with content %s on tcid %t at %s", rank, where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_mkdir            , "hsrfs %n mkdir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_search           , "hsrfs %n search %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_delete_file      , "hsrfs %n delete file %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_delete_dir       , "hsrfs %n delete dir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_delete_path      , "hsrfs %n delete path %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_delete_root_dir  , "hsrfs %n delete root dir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_recycle          , "hsrfs %n recycle on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_retire           , "hsrfs %n retire max %n files on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_flush            , "hsrfs %n flush on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_flush_npp        , "hsrfs %n flush npp on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_flush_dn         , "hsrfs %n flush dn on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_npp_lru_list, "hsrfs %n show npp lru on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_npp_del_list, "hsrfs %n show npp del on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_npp         , "hsrfs %n show npp on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_dn          , "hsrfs %n show dn on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_cached_np_lru_list, "hsrfs %n show cached np lru on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_cached_np_del_list, "hsrfs %n show cached np del on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_cached_np   , "hsrfs %n show cached np on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_specific_np_lru_list , "hsrfs %n show specific np %n lru on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_specific_np_del_list , "hsrfs %n show specific np %n del on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_specific_np , "hsrfs %n show specific np %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_show_locked_files, "hsrfs %n show locked files on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_md5sum           , "hsrfs %n md5sum file %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_count_file_num   , "hsrfs %n count file num of %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_count_file_size  , "hsrfs %n count file size of %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qfile            , "hsrfs %n qfile %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qdir             , "hsrfs %n qdir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qlist_path_of_np , "hsrfs %n qlist %s full of np %n on tcid %t at %s", rank, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qlist_seg_of_np  , "hsrfs %n qlist %s short of np %n on tcid %t at %s", rank, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qlist_tree_of_np , "hsrfs %n qlist %s tree of np %n on tcid %t at %s", rank, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qlist_path       , "hsrfs %n qlist %s full on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qlist_seg        , "hsrfs %n qlist %s short on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfs_qlist_tree       , "hsrfs %n qlist %s tree on tcid %t at %s", rank, where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_create_npp       , "hsxfs %n create np model %n max num %n with hash algo %n on tcid %t at %s", rank, rank, rank, rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_create_dn        , "hsxfs %n create dn on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_create_sata_bad_bitmap, "hsxfs %n create sata bad bitmap on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_set_sata_bad_page  , "hsxfs %n set sata bad page %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_unset_sata_bad_page, "hsxfs %n unset sata bad page %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_check_sata_bad_page, "hsxfs %n check sata bad page %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_sata_bad_pages, "hsxfs %n show sata bad pages on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_set_ssd_bad_page   , "hsxfs %n set ssd bad page %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_unset_ssd_bad_page , "hsxfs %n unset ssd bad page %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_check_ssd_bad_page , "hsxfs %n check ssd bad page %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_ssd_bad_pages , "hsxfs %n show ssd bad pages on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_add_disk         , "hsxfs %n add disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_del_disk         , "hsxfs %n del disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_mount_disk       , "hsxfs %n mount disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_umount_disk      , "hsxfs %n umount disk %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_open             , "hsxfs %n open from sata %s and ssd %s on tcid %t", rank, where, where, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_close            , "hsxfs %n close on tcid %t", rank, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_read             , "hsxfs %n read file %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_write            , "hsxfs %n write file %s with content %s on tcid %t at %s", rank, where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_mkdir            , "hsxfs %n mkdir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_search           , "hsxfs %n search %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_delete_file      , "hsxfs %n delete file %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_delete_dir       , "hsxfs %n delete dir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_delete_path      , "hsxfs %n delete path %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_delete_root_dir  , "hsxfs %n delete root dir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_recycle          , "hsxfs %n recycle on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_retire           , "hsxfs %n retire max %n files on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_flush            , "hsxfs %n flush on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_flush_npp        , "hsxfs %n flush npp on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_flush_dn         , "hsxfs %n flush dn on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_set_read_only    , "hsxfs %n set read only on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_unset_read_only  , "hsxfs %n unset read only on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_check_read_only  , "hsxfs %n check read only on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_sync             , "hsxfs %n sync on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_replay_op        , "hsxfs %n replay op on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_pop_op           , "hsxfs %n pop op  %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_npp_lru_list, "hsxfs %n show npp lru on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_npp_del_list, "hsxfs %n show npp del on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_npp         , "hsxfs %n show npp on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_dn          , "hsxfs %n show dn on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_specific_np_lru_list , "hsxfs %n show specific np %n lru on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_specific_np_del_list , "hsxfs %n show specific np %n del on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_specific_np , "hsxfs %n show specific np %n on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_show_locked_files, "hsxfs %n show locked files on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_md5sum           , "hsxfs %n md5sum file %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_count_file_num   , "hsxfs %n count file num of %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_count_file_size  , "hsxfs %n count file size of %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qfile            , "hsxfs %n qfile %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qdir             , "hsxfs %n qdir %s on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qlist_path_of_np , "hsxfs %n qlist %s full of np %n on tcid %t at %s", rank, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qlist_seg_of_np  , "hsxfs %n qlist %s short of np %n on tcid %t at %s", rank, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qlist_tree_of_np , "hsxfs %n qlist %s tree of np %n on tcid %t at %s", rank, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qlist_path       , "hsxfs %n qlist %s full on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qlist_seg        , "hsxfs %n qlist %s short on tcid %t at %s", rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cxfs_qlist_tree       , "hsxfs %n qlist %s tree on tcid %t at %s", rank, where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_open            , "hsrfsc open from root %s on tcid %t", where, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_close           , "hsrfsc close on tcid %t", tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_read            , "hsrfsc read file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_write           , "hsrfsc write file %s with content %s on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_search_file     , "hsrfsc search file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_search_dir      , "hsrfsc search dir %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_delete_file     , "hsrfsc delete file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_delete_dir      , "hsrfsc delete dir %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_delete_path     , "hsrfsc delete path %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_recycle         , "hsrfsc recycle on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_md5sum          , "hsrfsc md5sum file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_count_file_size , "hsrfsc count file size of %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_qfile           , "hsrfsc qfile %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_add_dir         , "hsrfsc add dir %s %t on tcid %t at %s", where, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_del_dir         , "hsrfsc del dir %s %t on tcid %t at %s", where, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_has_dir         , "hsrfsc has dir %s %t on tcid %t at %s", where, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_clone_dt        , "hsrfsc clone dt on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_rollback_dt     , "hsrfsc rollback dt on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_flush_dt        , "hsrfsc flush dt on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_load_dt         , "hsrfsc load dt on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_crfsc_show_dt         , "hsrfsc show dt on tcid %t at %s", tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_create_npp       , "hshfs create np model %n max num %n with root %s on tcid %t at %s", rank, rank, rank, rank, rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_create_dn        , "hshfs create dn with root %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_add_disk         , "hshfs add disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_del_disk         , "hshfs del disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_mount_disk       , "hshfs mount disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_umount_disk      , "hshfs umount disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_open             , "hshfs open from np root %s and dn root %s on tcid %t", where, where, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_close            , "hshfs close on tcid %t", tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_read             , "hshfs read file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_write            , "hshfs write file %s with content %s on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_search           , "hshfs search %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_qfile            , "hshfs qfile %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_delete           , "hshfs delete file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_recycle          , "hshfs recycle on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_retire           , "hshfs retire max %n files created before %n seconds on tcid %t at %s", rank, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_show_npp         , "hshfs show npp on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_show_dn          , "hshfs show dn on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_show_cached_np   , "hshfs show cached np on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_show_specific_np , "hshfs show specific np %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_count_file_num   , "hshfs count file num on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_chfs_count_file_size  , "hshfs count file size of %s on tcid %t at %s", where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_create_npp       , "hssfs create np model %n max num %n with root %s on tcid %t at %s", rank, rank, rank, rank, rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_create_dn        , "hssfs create dn with root %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_add_disk         , "hssfs add disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_del_disk         , "hssfs del disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_mount_disk       , "hssfs mount disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_umount_disk      , "hssfs umount disk %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_open             , "hssfs open from np root %s and dn root %s on tcid %t", where, where, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_close            , "hssfs close on tcid %t", tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_read             , "hssfs read file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_write            , "hssfs write file %s with content %s on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_search           , "hssfs search %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_qfile            , "hssfs qfile %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_delete           , "hssfs delete file %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_show_npp         , "hssfs show npp on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_show_dn          , "hssfs show dn on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_show_cached_np   , "hssfs show cached np on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_show_specific_np , "hssfs show specific np %n on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_count_file_num   , "hssfs count file num on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_csfs_count_file_size  , "hssfs count file size of %s on tcid %t at %s", where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_create_npp       , "tdns create np model %n max num %n with root %s on tcid %t at %s", rank, rank, rank, rank, rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_start            , "tdns start from root %s on tcid %t", where, where, tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_end              , "tdns end on tcid %t", tcid);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_config_tcid      , "tdns config service %s tcid %t port %n on tcid %t at %s", where, tcid, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_reserve_tcid     , "tdns reserve service %s ip %t on tcid %t at %s", where, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_release_tcid     , "tdns release service %s tcid %t port %n on tcid %t at %s", where, tcid, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_get_tcid         , "tdns get tcid %t on tcid %t at %s", tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_get_service      , "tdns get service %s max nodes %n on tcid %t at %s", where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_set_no_service   , "tdns set tcid %t ip %t port %n on tcid %t at %s", tcid, tcid, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_set_has_service  , "tdns set tcid %t ip %t port %n service %s on tcid %t at %s", tcid, tcid, rank, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_search_tcid      , "tdns search tcid %t on tcid %t at %s", tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_search_service   , "tdns search service %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_delete           , "tdns delete tcid %t on tcid %t at %s", tcid, tcid, where);
    //api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_online           , "tdns online service %s network %n tcid %t on tcid %t at %s", where, rank, tcid, tcid, where);
    //api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_offline          , "tdns offline service %s network %n tcid %t on tcid %t at %s", where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_refresh_cache    , "tdns refresh path %s service %s network %n tcid %t on tcid %t at %s", where, where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_show_npp         , "tdns show npp on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_show_svp         , "tdns show svp on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_count_tcid_num   , "tdns count tcid num on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_ctdns_count_node_num   , "tdns count service %s node num on tcid %t at %s", where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_cdetect_show_orig_nodes, "detect show orig nodes on tcid %t at %s", tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cdetect_show_orig_node , "detect show orig node %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cdetect_dns_resolve    , "detect dns resolve domain %s on tcid %t at %s", where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cdetect_process        , "detect process %n tasks on tcid %t at %s", rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cdetect_process_loop   , "detect loop process %n tasks on tcid %t at %s", rank, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_load              , "p2p upload %s to %s %s on tcid %t at %s", where, where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_upload            , "p2p upload %s to %s %s to tcid %t at %s", where, where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_download          , "p2p download %s %s from %t on tcid %t at %s", where, where, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_push              , "p2p push %s %s to network %n tcid %t on tcid %t at %s", where, where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_push_subnet       , "p2p push %s %s to network %n all on tcid %t at %s", where, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_push_all          , "p2p push %s %s to all on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_pull              , "p2p pull %s %s on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_delete            , "p2p delete %s %s in network %n tcid %t on tcid %t at %s", where, where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_delete_subnet     , "p2p delete %s %s in network %n all on tcid %t at %s", where, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_delete_all        , "p2p delete %s %s in all on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_flush             , "p2p flush %s %s to %s in network %n tcid %t on tcid %t at %s", where, where, where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_flush_subnet      , "p2p flush %s %s to %s in network %n all on tcid %t at %s", where, where, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_flush_all         , "p2p flush %s %s to %s in all on tcid %t at %s", where, where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_execute_cmd       , "p2p execute %s %s on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_deliver_cmd       , "p2p deliver %s %s in network %n tcid %t on tcid %t at %s", where, where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_deliver_cmd_subnet, "p2p deliver %s %s in network %n all on tcid %t at %s", where, where, rank, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_deliver_cmd_all   , "p2p deliver %s %s in all on tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_online            , "p2p online %s network %n tcid %t on tcid %t at %s", where, rank, tcid, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_cp2p_offline           , "p2p offline %s network %n tcid %t on tcid %t at %s", where, rank, tcid, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_download_file         , "download file %s to %s from tcid %t at %s", where, where, tcid, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_upload_file           , "upload file %s to %s on tcid %t at %s", where, where, tcid, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_log_level_all    , "show log level on all at %s"            , where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_show_log_level        , "show log level on tcid %t rank %n at %s", tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_set_log_level_tab_all , "set log level table to %n on all at %s", rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_set_log_level_tab     , "set log level table to %n on tcid %t rank %n at %s", rank, tcid, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_set_log_level_sec_all , "set log level sector %n to %n on all at %s", rank, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_set_log_level_sec     , "set log level sector %n to %n on tcid %t rank %n at %s", rank, rank, tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_say_hello             , "say hello to tcid %t rank %n on tcid %t rank %n at %s", tcid, rank, tcid, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_say_hello_all         , "say hello to tcid %t rank %n on all at %s", tcid, rank, where);

    api_cmd_comm_define(cmd_tree, api_cmd_ui_say_hello_loop        , "say hello loop %n to tcid %t rank %n on tcid %t rank %n at %s", rank, tcid, rank, tcid, rank, where);
    api_cmd_comm_define(cmd_tree, api_cmd_ui_say_hello_loop_all    , "say hello loop %n to tcid %t rank %n on all at %s", rank, tcid, rank, where);

    return (EC_TRUE);
}

void api_cmd_ui_do_script(CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec, char *script_name)
{
    FILE *script_fp;

    char   cmd_line[ 256 ];
    UINT32 cmd_line_len;

    script_fp = fopen(script_name, "r");
    if(NULL_PTR == script_fp)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_ui_do_script: open script %s failed\n", script_name);
        return;
    }

    cmd_line_len = sizeof(cmd_line)/sizeof(cmd_line[0]);

    while(fgets(cmd_line, cmd_line_len, script_fp))
    {
        UINT8 *cmd_line_ptr;
        cmd_line_ptr = api_cmd_greedy_space((UINT8 *)cmd_line, ((UINT8 *)cmd_line) + strlen((char *)cmd_line));

        if(NULL_PTR != cmd_line_ptr && '#' != cmd_line_ptr[0])
        {
            cmd_line_ptr[strlen((char *)cmd_line_ptr) - 1] = '\0';
            dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "##################################################################################\n");
            dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "CMD [%s]\n", cmd_line_ptr);
            dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "##################################################################################\n");
            api_cmd_ui_do_once(cmd_tree, cmd_help_vec, (char *)cmd_line_ptr);
        }
    }

    fclose(script_fp);
    return;
}
void api_cmd_ui_do_once(CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec, char *cmd_line)
{
    CMD_PARA_VEC *cmd_para_vec;
    UINT8 *cmd_line_ptr;

    cmd_line_ptr = api_cmd_greedy_space((UINT8 *)cmd_line, ((UINT8 *)cmd_line) + strlen((char *)cmd_line));
    if(NULL_PTR == cmd_line_ptr)
    {
        return;
    }

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "CMD [%s]\n", cmd_line_ptr);

    if(0 == strncasecmp((char *)cmd_line_ptr, "help", 4))
    {
        api_cmd_comm_help(LOGCONSOLE, cmd_help_vec);
        return;
    }

    if(0 == strncasecmp((char *)cmd_line_ptr, "script", 6))
    {
        char *fields[8];
        if(2 != c_str_split((char *)cmd_line_ptr, " \r\n\t", fields, 8))
        {
            api_cmd_comm_help(LOGCONSOLE, cmd_help_vec);
            return;
        }
        api_cmd_ui_do_script(cmd_tree, cmd_help_vec, fields[1]);
        return;
    }

    cmd_para_vec = api_cmd_para_vec_new();
    api_cmd_comm_parse(cmd_tree, cmd_line_ptr, cmd_para_vec);
    api_cmd_para_vec_free(cmd_para_vec);

    return;
}

EC_BOOL api_cmd_ui_task_once(CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec)
{
    char        *cmd;

    cmd = (char *)api_cmd_line_buff;

    api_cmd_ui_do_once(cmd_tree, cmd_help_vec, (char *)cmd);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_clear_cmd()
{
    char        *cmd;

    cmd = (char *)api_cmd_line_buff;

    cmd[ 0 ] = '\0';
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_get_cmd()
{
    const char  *prompt;
    char        *cmd;
    uint32_t     size;

    uint32_t     len;
    EC_BOOL      ret;

    prompt = api_cmd_prompt;
    cmd    = (char *)api_cmd_line_buff;
    size   = api_cmd_line_buff_size;

    ret = cconsole_cmd_get(prompt, cmd, size, &len);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_ui_get_cmd: quit console due to get cmd failed\n");
        csig_stop(SIGHUP);
        return (EC_FALSE);
    }

    if(EC_AGAIN == ret)
    {
        return (EC_TRUE);
    }

    /*quit*/
    if(EC_TRUE == c_str_is_in(cmd, (const char *)":", (const char *)"exit:quit"))
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:api_cmd_ui_get_cmd: quit console by cmd\n");
        csig_stop(SIGHUP);
        return (EC_FALSE);
    }

    /*add command to history*/
    cconsole_cmd_add_history(cmd);

    /*show history commands*/
    if(EC_TRUE == c_str_is_in(cmd, (const char *)":", (const char *)"history:his"))
    {
        cconsole_cmd_print_history(LOGCONSOLE);
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_init_ccond()
{
    api_cmd_ccond = c_cond_new(LOC_API_0029);
    if(NULL_PTR == api_cmd_ccond)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_clean_ccond()
{
    if(NULL_PTR != api_cmd_ccond)
    {
        c_cond_free(api_cmd_ccond, LOC_API_0030);
        api_cmd_ccond = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_readline_is_disabled()
{
    if(NULL_PTR != api_cmd_ccond)
    {
        if(0 < c_cond_spy(api_cmd_ccond, LOC_API_0031))
        {
            return (EC_TRUE);
        }

        return (EC_FALSE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_ui_readline_is_enabled()
{
    if(NULL_PTR != api_cmd_ccond)
    {
        if(0 == c_cond_spy(api_cmd_ccond, LOC_API_0032))
        {
            return (EC_TRUE);
        }

        return (EC_FALSE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_ui_readline_set_disabled()
{
    if(NULL_PTR != api_cmd_ccond)
    {
        c_cond_reserve(api_cmd_ccond, 1, LOC_API_0033);
        c_cond_wait(api_cmd_ccond, LOC_API_0034);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_ui_readline_set_enabled()
{
    if(NULL_PTR != api_cmd_ccond)
    {
        c_cond_release(api_cmd_ccond, LOC_API_0035);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL api_cmd_ui_task_preface()
{
    sys_print(LOGCONSOLE, "%32s------------------------------------------------------------\n", "");
    sys_print(LOGCONSOLE, "%32s|                                                          |\n", "");
    sys_print(LOGCONSOLE, "%32s|                WELCOME TO BGN CONSOLE UTILITY            |\n", "");
    sys_print(LOGCONSOLE, "%32s|                                                          |\n", "");
    sys_print(LOGCONSOLE, "%32s------------------------------------------------------------\n", "");

    return (EC_TRUE);
}

/*readline thread to get a command from console*/
EC_BOOL api_cmd_ui_task()
{
    cconsole_catach_signals_disable();

    api_cmd_ui_task_preface();

    for(;;)
    {
        dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_task: enter\n");
        if(EC_TRUE == api_cmd_ui_readline_is_enabled())
        {
            dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_task: readline is enabled\n");
            api_cmd_ui_clear_cmd();
            api_cmd_ui_get_cmd();
            dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_task: readline set disabled\n");
            api_cmd_ui_readline_set_disabled();
        }
    }

    cconsole_cmd_clear_history();

    return (EC_FALSE);
}

STATIC_CAST static MOD_MGR *api_cmd_ui_gen_mod_mgr(const UINT32 incl_tcid, const UINT32 incl_rank, const UINT32 excl_tcid, const UINT32 excl_rank, const UINT32 modi)
{
    TASK_BRD  *task_brd;
    TASKC_MGR *taskc_mgr;

    MOD_MGR *mod_mgr;

    task_brd = task_brd_default_get();

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);

    taskc_mgr = taskc_mgr_new();
    task_brd_sync_taskc_mgr(task_brd, taskc_mgr);
    mod_mgr_gen_by_taskc_mgr(taskc_mgr, incl_tcid, incl_rank, modi, mod_mgr);
    taskc_mgr_free(taskc_mgr);

    mod_mgr_excl(excl_tcid, CMPI_ANY_COMM, excl_rank, modi, mod_mgr);

    if(0 == MOD_MGR_REMOTE_NUM(mod_mgr))
    {
        UINT32      incl_ipv4;
        UINT32      incl_port;

        if(EC_TRUE == c_tdns_resolve(incl_tcid, &incl_ipv4, &incl_port))
        {
            MOD_NODE   *remote_mod_node;

            dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_gen_mod_mgr: "
                                                "tdns resolve '%s' => ip '%s', port %ld\n",
                                                c_word_to_ipv4(incl_tcid),
                                                c_word_to_ipv4(incl_ipv4),
                                                incl_port);

            mod_node_alloc(&remote_mod_node);

            MOD_NODE_TCID(remote_mod_node) = incl_tcid;
            MOD_NODE_COMM(remote_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(remote_mod_node) = incl_rank;
            MOD_NODE_MODI(remote_mod_node) = modi;

            cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr), remote_mod_node);
        }
    }

    return (mod_mgr);
}

STATIC_CAST static LOG *api_cmd_ui_get_log(const CSTRING *where)
{
    if(0 == strcmp("log", (char *)cstring_get_str(where)))
    {
        dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_get_log: return LOGSTDOUT\n");
        return (LOGSTDOUT);
    }

    if(0 == strcmp("console", (char *)cstring_get_str(where)))
    {
        dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_get_log: return LOGCONSOLE\n");
        return (LOGCONSOLE);
    }
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_get_log: return LOGSTDNULL\n");
    return (LOGSTDNULL);
}

EC_BOOL api_cmd_ui_dns_resolve_demo(CMD_PARA_VEC * param)
{
    CSTRING *domain;
    CSTRING *dns_server;
    CSTRING *where;
    UINT32   tcid;
    UINT32   rank;

    MOD_NODE    mod_node;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &domain);
    api_cmd_para_vec_get_cstring(param , 1, &dns_server);
    api_cmd_para_vec_get_tcid(param    , 2, &tcid);
    api_cmd_para_vec_get_uint32(param  , 3, &rank);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "dns resolve %s from %s on tcid %s rank %ld at %s\n",
                        (char *)cstring_get_str(domain),
                        (char *)cstring_get_str(dns_server),
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = rank;
    MOD_NODE_MODI(&mod_node) = 0;/*super_md_id = 0*/

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_super_dns_resolve_demo, CMPI_ERROR_MODI, dns_server, domain);

    if(EC_TRUE == ret)
    {
        sys_log(LOGCONSOLE, "[SUCC]\n");
    }
    else
    {
        sys_log(LOGCONSOLE, "[FAIL]\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_activate_sys_cfg(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "act sysconfig on tcid %s rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_activate_sys_cfg beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_activate_sys_cfg end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_activate_sys_cfg, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);
    sys_log(des_log, "done\n");

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_activate_sys_cfg_all(CMD_PARA_VEC * param)
{
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    LOG *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "act sysconfig on all at %s\n",
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_activate_sys_cfg_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_activate_sys_cfg_all end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_activate_sys_cfg, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);
    sys_log(des_log, "done\n");

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_sys_cfg(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show sysconfig on tcid %s rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_sys_cfg beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_sys_cfg end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0036);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_sys_cfg, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0037);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_sys_cfg_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show sysconfig on all at %s\n",
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_sys_cfg_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_sys_cfg_all end ----------------------------------\n");
    }
#endif
    report_vec = cvector_new(0, MM_LOG, LOC_API_0038);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();
        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_sys_cfg, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0039);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_show_mem(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show mem all on tcid %s rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0040);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_mem, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0041);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_mem_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show mem all on all at %s\n",
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0042);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();
        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_mem, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0043);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_show_mem_of_type(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 type;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_uint32(param, 0, &type);
    api_cmd_para_vec_get_tcid(param, 1, &tcid);
    api_cmd_para_vec_get_uint32(param, 2, &rank);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "type = %ld, tcid = %s, rank = %ld, where = %s\n",
                        type,
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem_of_type beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem_of_type end ----------------------------------\n");
    }
#endif
    report_vec = cvector_new(0, MM_LOG, LOC_API_0044);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_mem_of_type, CMPI_ERROR_MODI, type, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0045);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_mem_all_of_type(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;
    UINT32   type;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param, 0, &type);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_show_mem_all_of_type type = %ld where = %s\n", type, (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem_all_of_type beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_mem_all_of_type end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0046);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();
        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_mem_of_type, CMPI_ERROR_MODI, type, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0047);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_diag_mem(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "tcid = %s, rank = %ld, where = %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0048);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_diag_mem, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0049);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_diag_mem_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_diag_mem_all where = %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0050);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_diag_mem, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0051);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_diag_mem_of_type(CMD_PARA_VEC * param)
{
    UINT32 type;
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param, 0, &type);
    api_cmd_para_vec_get_tcid(param, 1, &tcid);
    api_cmd_para_vec_get_uint32(param, 2, &rank);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "type = %ld, tcid = %s, rank = %ld, where = %s\n",
                        type,
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem_of_type beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem_of_type end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0052);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_diag_mem_of_type, CMPI_ERROR_MODI, type, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0053);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_diag_mem_all_of_type(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;
    UINT32 type;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param, 0, &type);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_diag_mem_all_of_type type = %ld where = %s\n", type, (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem_all_of_type beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_mem_all_of_type end ----------------------------------\n");
    }
#endif
    report_vec = cvector_new(0, MM_LOG, LOC_API_0054);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_diag_mem_of_type, CMPI_ERROR_MODI, type, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0055);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_diag_csocket_cnode(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "tcid = %s, rank = %ld, where = %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_csocket_cnode beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_csocket_cnode end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0056);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_diag_csocket_cnode, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0057);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_diag_csocket_cnode_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_diag_csocket_cnode_all where = %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_csocket_cnode_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_diag_csocket_cnode_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0058);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_diag_csocket_cnode, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0059);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_clean_mem(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "tcid = %s, rank = %ld\n",
                       c_word_to_ipv4(tcid),
                       rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_clean_mem beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_clean_mem end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_clean_mem, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_clean_mem_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_clean_mem_all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_clean_mem_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_clean_mem_all end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_clean_mem, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_breathing_mem(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "breathing mem on tcid %s, rank %ld\n",
                       c_word_to_ipv4(tcid),
                       rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_breathing_mem beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_breathing_mem end ----------------------------------\n");
    }
#endif

#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_breathing_mem, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_breathing_mem_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "breathing mem on all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_breathing_mem_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_breathing_mem_all end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_breathing_mem, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_show_log_level(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show log level on tcid %s rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_log_level beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_log_level end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0060);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_log_level_tab, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0061);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_log_level_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show log level on all at %s\n",
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_log_level_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_log_level_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0062);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();
        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_log_level_tab, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0063);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_set_log_level_tab(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    level;
    UINT32    tcid;
    UINT32    rank;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &level);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_uint32(param , 2, &rank);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    /*set log level tablele to %n on tcid %t rank %n at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "set log level table to %ld on tcid %s rank %ld at %s\n",
                        level,
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_tab beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_tab end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0064);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0065);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_set_log_level_tab, CMPI_ERROR_MODI, level);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld] SUCC\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] FAIL\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0066);
    }

    cvector_free(report_vec, LOC_API_0067);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_set_log_level_tab_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    level;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &level);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    /*set log level tablele to %n on all at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "set log level table to %ld on all at %s\n",
                        level, (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_tab_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_tab_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0068);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0069);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_set_log_level_tab, CMPI_ERROR_MODI, level);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld] SUCC\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] FAIL\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0070);
    }

    cvector_free(report_vec, LOC_API_0071);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_set_log_level_sec(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    sector;
    UINT32    level;
    UINT32    tcid;
    UINT32    rank;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &sector);
    api_cmd_para_vec_get_uint32(param , 1, &level);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_cstring(param, 4, &where);

    /*set log level sector %n to %n on tcid %t rank %n at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "set log level sector %ld to %ld on tcid %s rank %ld at %s\n",
                        sector,
                        level,
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_sec beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_sec end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0072);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0073);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_set_log_level_sector, CMPI_ERROR_MODI, sector, level);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld] SUCC\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] FAIL\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0074);
    }

    cvector_free(report_vec, LOC_API_0075);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_set_log_level_sec_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    sector;
    UINT32    level;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &sector);
    api_cmd_para_vec_get_uint32(param , 1, &level);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    /*set log level sector %n to %n on all at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "set log level sector %ld to %ld on all at %s\n",
                        sector,
                        level,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_sec_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_log_level_sec_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0076);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0077);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_set_log_level_sector, CMPI_ERROR_MODI, sector, level);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld] SUCC\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] FAIL\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0078);
    }

    cvector_free(report_vec, LOC_API_0079);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_say_hello(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    des_tcid;
    UINT32    des_rank;
    UINT32    tcid;
    UINT32    rank;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *hello_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param   , 0, &des_tcid);
    api_cmd_para_vec_get_uint32(param , 1, &des_rank);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_cstring(param, 4, &where);

    /*say hello to tcid %t rank %n on tcid %t rank %n at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "say hello to tcid %s rank %ld on tcid %s rank %ld at %s\n",
                        c_word_to_ipv4(des_tcid),
                        des_rank,
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0080);
    hello_vec = cvector_new(0, MM_CSTRING, LOC_API_0081);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;
        CSTRING *cstring;

        cstring = cstring_new(NULL_PTR, LOC_API_0082);
        cvector_push(hello_vec, (void *)cstring);

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0083);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_say_hello, CMPI_ERROR_MODI, des_tcid, des_rank, cstring);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;
        CSTRING  *cstring;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        cstring = (CSTRING *)cvector_get(hello_vec, remote_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC] %s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), cstring_get_str(cstring));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(hello_vec, remote_mod_node_idx, NULL_PTR);
        cstring_free(cstring);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0084);

    }

    cvector_free(hello_vec, LOC_API_0085);
    cvector_free(report_vec, LOC_API_0086);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_say_hello_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    des_tcid;
    UINT32    des_rank;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *hello_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param   , 0, &des_tcid);
    api_cmd_para_vec_get_uint32(param , 1, &des_rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    /*say hello to tcid %t rank %n on tcid %t rank %n at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "say hello to tcid %s rank %ld on all at %s\n",
                        c_word_to_ipv4(des_tcid),
                        des_rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0087);
    hello_vec = cvector_new(0, MM_CSTRING, LOC_API_0088);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;
        CSTRING *cstring;

        cstring = cstring_new(NULL_PTR, LOC_API_0089);
        cvector_push(hello_vec, (void *)cstring);

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0090);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_say_hello, CMPI_ERROR_MODI, des_tcid, des_rank, cstring);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;
        CSTRING  *cstring;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        cstring = (CSTRING *)cvector_get(hello_vec, remote_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC] %s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), cstring_get_str(cstring));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(hello_vec, remote_mod_node_idx, NULL_PTR);
        cstring_free(cstring);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0091);

    }

    cvector_free(hello_vec, LOC_API_0092);
    cvector_free(report_vec, LOC_API_0093);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_say_hello_loop(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    loops;
    UINT32    des_tcid;
    UINT32    des_rank;
    UINT32    tcid;
    UINT32    rank;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &loops);
    api_cmd_para_vec_get_tcid(param   , 1, &des_tcid);
    api_cmd_para_vec_get_uint32(param , 2, &des_rank);
    api_cmd_para_vec_get_tcid(param   , 3, &tcid);
    api_cmd_para_vec_get_uint32(param , 4, &rank);
    api_cmd_para_vec_get_cstring(param, 5, &where);

    /*say hello loop to tcid %t rank %n on tcid %t rank %n at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "say hello loop %ld to tcid %s rank %ld on tcid %s rank %ld at %s\n",
                        loops,
                        c_word_to_ipv4(des_tcid),
                        des_rank,
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello_loop beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello_loop end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0094);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0095);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_say_hello_loop, CMPI_ERROR_MODI, loops, des_tcid, des_rank);
    }
    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0096);

    }

    cvector_free(report_vec, LOC_API_0097);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_say_hello_loop_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    UINT32    loops;
    UINT32    des_tcid;
    UINT32    des_rank;
    CSTRING  *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG     *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &loops);
    api_cmd_para_vec_get_tcid(param   , 1, &des_tcid);
    api_cmd_para_vec_get_uint32(param , 2, &des_rank);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    /*say hello loop to tcid %t rank %n on all at %s*/
    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "say hello loop %ld to tcid %s rank %ld on all at %s\n",
                        loops,
                        c_word_to_ipv4(des_tcid),
                        des_rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello_loop_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_say_hello_loop_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0098);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0099);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_say_hello_loop, CMPI_ERROR_MODI, loops, des_tcid, des_rank);
    }
    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0100);
    }

    cvector_free(report_vec, LOC_API_0101);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_switch_log(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 on_off;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_uint32(param, 2, &on_off);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "switch tcid %s, rank %ld log to %ld\n",
                        c_word_to_ipv4((tcid)),
                        rank,
                        on_off);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_log beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_log end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        if(SWITCH_OFF == on_off)/*off*/
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_log_off, CMPI_ERROR_MODI);
        }
        else
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_log_on, CMPI_ERROR_MODI);
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_switch_log_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    UINT32 on_off;

    api_cmd_para_vec_get_uint32(param, 0, &on_off);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "switch all log to %ld\n", on_off);

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_log_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_log_all end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        if(SWITCH_OFF == on_off)/*off*/
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_log_off, CMPI_ERROR_MODI);
        }
        else
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_log_on, CMPI_ERROR_MODI);
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_rotate_log(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 log_index;
    CSTRING *where;

    LOG      *des_log;
    EC_BOOL   ret;

    MOD_NODE  mod_node;

    api_cmd_para_vec_get_uint32(param , 0, &log_index);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_uint32(param , 2, &rank);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "rotate log %ld on tcid %s, rank %ld at %s\n",
                        log_index,
                        c_word_to_ipv4((tcid)),
                        rank,
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = rank;
    MOD_NODE_MODI(&mod_node) = 0;/*super_md_id = 0*/

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_super_rotate_log, CMPI_ERROR_MODI, log_index);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] log rotate done\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] log rotate failed\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_rotate_log_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    UINT32 log_index;
    CSTRING *where;

    LOG      *des_log;
    CVECTOR  *report_vec;

    api_cmd_para_vec_get_uint32(param , 0, &log_index);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "rotate log %ld on all at %s\n",
                        log_index,
                        (char *)cstring_get_str(where));

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0102);

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0103);
        cvector_push(report_vec, (void *)ret);

        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_rotate_log, CMPI_ERROR_MODI, log_index);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32   *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld] SUCC\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] FAIL\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0104);
    }

    cvector_free(report_vec, LOC_API_0105);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_do_test(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    LOG      *des_log;
    EC_BOOL   ret;

    MOD_NODE  mod_node;

    api_cmd_para_vec_get_tcid(param   , 0, &tcid);
    api_cmd_para_vec_get_uint32(param , 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "do test on tcid %s, rank %ld at %s\n",
                        c_word_to_ipv4((tcid)),
                        rank,
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = rank;
    MOD_NODE_MODI(&mod_node) = 0;/*super_md_id = 0*/

    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_super_do_test, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] test done\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] test failed\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_switch_ngx_memc(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 on_off;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_uint32(param, 2, &on_off);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "switch ngx memc on tcid %s, rank %ld to %ld\n",
                        c_word_to_ipv4((tcid)),
                        rank,
                        on_off);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_ngx_memc beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_ngx_memc end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        if(SWITCH_OFF == on_off)/*off*/
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_ngx_memc_off, CMPI_ERROR_MODI);
        }
        else
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_ngx_memc_on, CMPI_ERROR_MODI);
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_switch_ngx_memc_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    UINT32 on_off;

    api_cmd_para_vec_get_uint32(param, 0, &on_off);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "switch ngx memc on all to %ld\n", on_off);

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_ngx_memc_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_switch_ngx_memc_all end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        if(SWITCH_OFF == on_off)/*off*/
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_ngx_memc_off, CMPI_ERROR_MODI);
        }
        else
        {
            task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_ngx_memc_on, CMPI_ERROR_MODI);
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_enable_to_rank_node(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 des_rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_uint32(param, 2, &des_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enable tcid %s rank %ld to rank %ld\n",
                        c_word_to_ipv4((tcid)),
                        rank,
                        des_rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_to_rank_node beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_to_rank_node end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_rank_node_green, CMPI_ERROR_MODI, (des_rank));
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_enable_all_to_rank_node(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    UINT32 des_rank;

    api_cmd_para_vec_get_uint32(param, 0, &des_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "disable all to rank %ld\n", des_rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_all_to_rank_node beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_all_to_rank_node end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_rank_node_green, CMPI_ERROR_MODI, (des_rank));
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_disable_to_rank_node(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    UINT32 des_rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_uint32(param, 2, &des_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "disable tcid %s rank %ld to rank %ld\n", c_word_to_ipv4((tcid)), rank, des_rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_to_rank_node beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_to_rank_node end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_rank_node_red, CMPI_ERROR_MODI, (des_rank));
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_disable_all_to_rank_node(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    UINT32 des_rank;

    api_cmd_para_vec_get_uint32(param, 0, &des_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "disable all to rank %ld\n", des_rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_all_to_rank_node beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_all_to_rank_node end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_switch_rank_node_red, CMPI_ERROR_MODI, (des_rank));
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_queue(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;

    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show queue on tcid %s, rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_queue beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_queue end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0106);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_queues, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0107);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_queue_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show queue on all at %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_queue_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_queue_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0108);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_queues, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0109);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_check_slowdown(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;

    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "check slow down on tcid %s, rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_check_slowdown beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_check_slowdown end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0110);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_check_slowdown, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0111);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_check_slowdown_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "check slow down on all at %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_check_slowdown_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_check_slowdown_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0112);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_check_slowdown, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0113);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_client(CMD_PARA_VEC * param)
{
    UINT32 tcid;

    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show client tcid %s where %s\n", c_word_to_ipv4(tcid), (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_client beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_client end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0114);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_work_client, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0115);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_client_all(CMD_PARA_VEC * param)
{
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show client all where = %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_client_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_client_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0116);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_work_client, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0117);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_thread(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "tcid = %s, rank = %ld, where = %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_thread beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_thread end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0118);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_thread_num, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0119);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_thread_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_show_thread_all where = %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_thread_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_thread_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0120);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_thread_num, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0121);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_show_route(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "tcid = %s, where = %s\n",
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_route beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_route end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0122);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_route_table, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0123);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_route_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_show_route_all where = %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_route_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_route_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0124);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_route_table, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0125);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_show_rank_node(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "tcid = %s, rank = %ld, where = %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_node beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_node end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0126);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_rank_node, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0127);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_rank_node_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enter api_cmd_ui_show_rank_node_all where = %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_node_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_node_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0128);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_rank_node, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0129);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);

}

EC_BOOL api_cmd_ui_show_rank_load(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show rank load on tcid %s rank %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_load beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_load end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0130);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_rank_load, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0131);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_rank_load_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show rank load on all at %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_load_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_rank_load_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0132);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_rank_load, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0133);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_shutdown_work(CMD_PARA_VEC * param)
{
    UINT32 tcid;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "shutdown work tcid %s\n", c_word_to_ipv4(tcid));

    if(EC_TRUE == task_brd_check_is_dbg_tcid(tcid))
    {
        dbg_log(SEC_0010_API, 0)(LOGSTDOUT, "error:tcid = %s is debug taskcomm\n", c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_work beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_work end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);/*mod_mgr will be freed automatically if calling task_no_wait*/
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_shutdown_work_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    //TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "shutdown work all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
    mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_FWD_RANK, CMPI_ANY_MODI, mod_mgr);
    mod_mgr_excl(CMPI_ANY_MON_TCID, CMPI_ANY_COMM, CMPI_FWD_RANK, CMPI_ANY_MODI, mod_mgr);

#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_work_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_work_all end ----------------------------------\n");
    }
#endif
#if 0
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);/*mod_mgr will be freed automatically if calling task_no_wait*/
#endif

#if 1
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_mono(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, remote_mod_node_idx,
                      NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_shutdown_dbg(CMD_PARA_VEC * param)
{
    UINT32 tcid;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "shutdown dbg tcid %s\n", c_word_to_ipv4(tcid));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_dbg beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_dbg end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);/*mod_mgr will be freed automatically if calling task_no_wait*/
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_shutdown_dbg_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "shutdown dbg all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_DBG_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ANY_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_dbg_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_dbg_all end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);/*mod_mgr will be freed automatically if calling task_no_wait*/
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_shutdown_mon(CMD_PARA_VEC * param)
{
    UINT32 tcid;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "shutdown mon tcid %s\n", c_word_to_ipv4(tcid));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_mon beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_mon end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);/*mod_mgr will be freed automatically if calling task_no_wait*/
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_shutdown_mon_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "shutdown mon all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_MON_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ANY_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_mon_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_shutdown_mon_all end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_shutdown_taskcomm, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);/*mod_mgr will be freed automatically if calling task_no_wait*/
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_taskcomm(CMD_PARA_VEC * param)
{
    UINT32  tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;
    UINT32 ret;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show taskcomm tcid %s where = %s\n", c_word_to_ipv4(tcid), (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_taskcomm beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_taskcomm end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0134);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        TASKC_MGR *taskc_mgr;

        taskc_mgr = taskc_mgr_new();

        cvector_push(report_vec, (void *)taskc_mgr);
        task_pos_inc(task_mgr, remote_mod_node_idx, &ret, FI_super_sync_taskc_mgr, CMPI_ERROR_MODI, taskc_mgr);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        TASKC_MGR *taskc_mgr;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        taskc_mgr = (TASKC_MGR *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        taskc_mgr_print(des_log, taskc_mgr);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        taskc_mgr_free(taskc_mgr);
    }

    cvector_free(report_vec, LOC_API_0135);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_taskcomm_all(CMD_PARA_VEC * param)
{
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;
    UINT32 ret;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show taskcomm all at %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_taskcomm_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_taskcomm_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0136);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        TASKC_MGR *taskc_mgr;

        taskc_mgr = taskc_mgr_new();

        cvector_push(report_vec, (void *)taskc_mgr);
        task_pos_inc(task_mgr, remote_mod_node_idx, &ret, FI_super_sync_taskc_mgr, CMPI_ERROR_MODI, taskc_mgr);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        TASKC_MGR *taskc_mgr;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        taskc_mgr = (TASKC_MGR  *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        taskc_mgr_print(des_log, taskc_mgr);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        taskc_mgr_free(taskc_mgr);
    }

    cvector_free(report_vec, LOC_API_0137);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_add_route(CMD_PARA_VEC * param)
{
    UINT32 des_tcid;
    UINT32 maskr;
    UINT32 next_tcid;
    UINT32 on_tcid;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &des_tcid);
    api_cmd_para_vec_get_mask(param, 1, &maskr);
    api_cmd_para_vec_get_tcid(param, 2, &next_tcid);
    api_cmd_para_vec_get_tcid(param, 3, &on_tcid);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "add route des_tcid = %s maskr = %s next_tcid = %s on tcid = %s\n",
                        c_word_to_ipv4(des_tcid), c_word_to_ipv4(maskr), c_word_to_ipv4(next_tcid), c_word_to_ipv4(on_tcid));

    mod_mgr = api_cmd_ui_gen_mod_mgr(on_tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_add_route beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_add_route end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL, FI_super_add_route, CMPI_ERROR_MODI, des_tcid, maskr, next_tcid);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_del_route(CMD_PARA_VEC * param)
{
    UINT32 des_tcid;
    UINT32 maskr;
    UINT32 next_tcid;
    UINT32 on_tcid;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &des_tcid);
    api_cmd_para_vec_get_mask(param, 1, &maskr);
    api_cmd_para_vec_get_tcid(param, 2, &next_tcid);
    api_cmd_para_vec_get_tcid(param, 3, &on_tcid);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "del route des_tcid = %s maskr = %s next_tcid = %s on tcid = %s\n",
                        c_word_to_ipv4(des_tcid), c_word_to_ipv4(maskr), c_word_to_ipv4(next_tcid), c_word_to_ipv4(on_tcid));

    mod_mgr = api_cmd_ui_gen_mod_mgr(on_tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_del_route beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_del_route end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL, FI_super_del_route, CMPI_ERROR_MODI, des_tcid, maskr, next_tcid);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_add_conn(CMD_PARA_VEC * param)
{
    UINT32 conn_num;
    UINT32 des_tcid;
    UINT32 des_srv_ipaddr;
    UINT32 des_srv_port;
    UINT32 on_tcid;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_uint32(param, 0, &conn_num);
    api_cmd_para_vec_get_tcid(param  , 1, &des_tcid);
    api_cmd_para_vec_get_ipaddr(param, 2, &des_srv_ipaddr);
    api_cmd_para_vec_get_uint32(param, 3, &des_srv_port);
    api_cmd_para_vec_get_tcid(param  , 4, &on_tcid);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "add %ld conn to tcid = %s ipaddr = %s port = %ld on tcid = %s\n",
                        conn_num,
                        c_word_to_ipv4(des_tcid),
                        c_word_to_ipv4(des_srv_ipaddr),
                        des_srv_port,
                        c_word_to_ipv4(on_tcid));

    mod_mgr = api_cmd_ui_gen_mod_mgr(on_tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_add_conn beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_add_conn end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL, FI_super_add_connection, CMPI_ERROR_MODI, des_tcid, des_srv_ipaddr, des_srv_port, conn_num);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_add_conn_all(CMD_PARA_VEC * param)
{
    UINT32 conn_num;
    UINT32 des_tcid;
    UINT32 des_srv_ipaddr;
    UINT32 des_srv_port;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_uint32(param, 0, &conn_num);
    api_cmd_para_vec_get_tcid(param  , 1, &des_tcid);
    api_cmd_para_vec_get_ipaddr(param, 2, &des_srv_ipaddr);
    api_cmd_para_vec_get_uint32(param, 3, &des_srv_port);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "add %ld conn to tcid = %s ipaddr = %s port = %ld on all\n",
                        conn_num,
                        c_word_to_ipv4(des_tcid),
                        c_word_to_ipv4(des_srv_ipaddr),
                        des_srv_port);

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);

#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_add_conn_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_add_conn_all end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL, FI_super_add_connection, CMPI_ERROR_MODI, des_tcid, des_srv_ipaddr, des_srv_port, conn_num);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_run_shell(CMD_PARA_VEC * param)
{
    UINT32 tcid;

    CSTRING *cmd_line;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    //cmd_line = cstring_new(NULL_PTR, LOC_API_0138);

    api_cmd_para_vec_get_cstring(param, 0, &cmd_line);
    api_cmd_para_vec_get_tcid(param, 1, &tcid);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "run shell %s on tcid %s where %s\n", (char *)cstring_get_str(cmd_line), c_word_to_ipv4(tcid), (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_run_shell beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_run_shell end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0139);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_run_shell, CMPI_ERROR_MODI, cmd_line, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG  *log;
        char *str;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);
        str = (char *)cstring_get_str(LOG_CSTR(log));

        sys_log(des_log, "[rank_%s_%ld] %s\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(cmd_line),
                         NULL_PTR == str ? "(null)\n" : str);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0140);
    mod_mgr_free(mod_mgr);

    //cstring_free(cmd_line);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_run_shell_all(CMD_PARA_VEC * param)
{
    CSTRING *cmd_line;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    //cmd_line = cstring_new(NULL_PTR, LOC_API_0141);
    api_cmd_para_vec_get_cstring(param, 0, &cmd_line);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "run shell %s all where = %s\n", (char *)cstring_get_str(cmd_line), (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_run_shell_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_run_shell_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0142);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_run_shell, CMPI_ERROR_MODI, cmd_line, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;
        char *str;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);
        str = (char *)cstring_get_str(LOG_CSTR(log));

        sys_log(des_log, "[rank_%s_%ld] %s\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(cmd_line),
                          NULL_PTR == str ? "(null)\n" : str);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0143);
    mod_mgr_free(mod_mgr);

    //cstring_free(cmd_line);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ping_taskcomm(CMD_PARA_VEC * param)
{
    UINT32  tcid;
    CSTRING *where;

    TASK_MGR *task_mgr;

    MOD_NODE send_mod_node;
    MOD_NODE recv_mod_node;

    LOG   *des_log;
    EC_BOOL ret;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    des_log = api_cmd_ui_get_log(where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show taskcomm tcid %s where = %s\n", c_word_to_ipv4(tcid), (char *)cstring_get_str(where));

    ret = EC_FALSE; /*initialization*/

    sys_log(des_log, "ping tcid %s ....\n", c_word_to_ipv4(tcid));

    task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = 0;
    MOD_NODE_HOPS(&send_mod_node) = 0;
    MOD_NODE_LOAD(&send_mod_node) = 0;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;
    MOD_NODE_HOPS(&recv_mod_node) = 0;
    MOD_NODE_LOAD(&recv_mod_node) = 0;

    task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_super_ping_taskcomm, CMPI_ERROR_MODI);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "tcid %s is reachable\n", c_word_to_ipv4(tcid));
    }
    else
    {
        sys_log(des_log, "tcid %s is unreachable\n", c_word_to_ipv4(tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_taskcfgchk_net(CMD_PARA_VEC * param)
{
    xmlDocPtr  task_cfg_doc;
    xmlNodePtr task_cfg_root;

    UINT32 tcid;
    CSTRING *where;

    LOG *des_log;

    SYS_CFG *sys_cfg;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    des_log = api_cmd_ui_get_log(where);

    /*parse config xml*/
    task_cfg_doc  = cxml_new((UINT8 *)task_brd_default_sys_cfg_xml());
    task_cfg_root = cxml_get_root(task_cfg_doc);

    sys_cfg = sys_cfg_new();
    //cxml_parse_task_cfg(task_cfg_root, task_cfg);
    cxml_parse_sys_cfg(task_cfg_root, sys_cfg);
    cxml_free(task_cfg_doc);

    //task_cfg_check_all(task_cfg);
    dbg_log(SEC_0010_API, 0)(LOGCONSOLE, "api_cmd_ui_taskcfgchk_net: %s: \n", (char *)task_brd_default_sys_cfg_xml());
    sys_cfg_print_xml(LOGSTDOUT, sys_cfg, 0);

    taskcfgchk_net_print(des_log, sys_cfg_get_task_cfg(sys_cfg), tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);

    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_taskcfgchk_net_all(CMD_PARA_VEC * param)
{
    xmlDocPtr  task_cfg_doc;
    xmlNodePtr task_cfg_root;

    CSTRING *where;

    LOG *des_log;

    SYS_CFG *sys_cfg;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    des_log = api_cmd_ui_get_log(where);

    /*parse config xml*/
    task_cfg_doc  = cxml_new((UINT8 *)task_brd_default_sys_cfg_xml());
    task_cfg_root = cxml_get_root(task_cfg_doc);

    sys_cfg = sys_cfg_new();
    //cxml_parse_task_cfg(task_cfg_root, task_cfg);
    cxml_parse_sys_cfg(task_cfg_root, sys_cfg);
    cxml_free(task_cfg_doc);

    taskcfgchk_net_all(des_log, sys_cfg_get_task_cfg(sys_cfg));

    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_taskcfgchk_route(CMD_PARA_VEC * param)
{
    xmlDocPtr  task_cfg_doc;
    xmlNodePtr task_cfg_root;

    UINT32 tcid;
    CSTRING *where;

    LOG *des_log;

    SYS_CFG *sys_cfg;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    des_log = api_cmd_ui_get_log(where);

    /*parse config xml*/
    task_cfg_doc  = cxml_new((UINT8 *)task_brd_default_sys_cfg_xml());
    task_cfg_root = cxml_get_root(task_cfg_doc);

    sys_cfg = sys_cfg_new();
    //cxml_parse_task_cfg(task_cfg_root, task_cfg);
    cxml_parse_sys_cfg(task_cfg_root, sys_cfg);
    cxml_free(task_cfg_doc);

    taskcfgchk_route_print(des_log, sys_cfg_get_task_cfg(sys_cfg), tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);

    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_taskcfgchk_route_trace(CMD_PARA_VEC * param)
{
    xmlDocPtr  task_cfg_doc;
    xmlNodePtr task_cfg_root;

    UINT32 src_tcid;
    UINT32 des_tcid;
    UINT32 max_hops;
    CSTRING *where;

    LOG *des_log;

    SYS_CFG *sys_cfg;

    api_cmd_para_vec_get_tcid(param, 0, &src_tcid);
    api_cmd_para_vec_get_tcid(param, 1, &des_tcid);
    api_cmd_para_vec_get_uint32(param, 2, &max_hops);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    des_log = api_cmd_ui_get_log(where);

    /*parse config xml*/
    task_cfg_doc  = cxml_new((UINT8 *)task_brd_default_sys_cfg_xml());
    task_cfg_root = cxml_get_root(task_cfg_doc);

    sys_cfg = sys_cfg_new();
    //cxml_parse_task_cfg(task_cfg_root, task_cfg);
    cxml_parse_sys_cfg(task_cfg_root, sys_cfg);
    cxml_free(task_cfg_doc);

    taskcfgchk_route_trace(des_log, sys_cfg_get_task_cfg(sys_cfg), src_tcid, CMPI_ANY_MASK, CMPI_ANY_MASK, des_tcid, max_hops);

    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_sync_taskcomm_from_local(CMD_PARA_VEC * param)
{
    UINT32 hops;
    UINT32 remotes;
    UINT32 time_to_live;
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    CVECTOR *report_vec;
    LOG *des_log;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_uint32(param , 0, &hops);
    api_cmd_para_vec_get_uint32(param , 1, &remotes);
    api_cmd_para_vec_get_uint32(param , 2, &time_to_live);
    api_cmd_para_vec_get_tcid(param   , 3, &tcid);
    api_cmd_para_vec_get_cstring(param, 4, &where);


    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "sync taskcomm hops %ld remotes %ld ttl %ld on tcid %s at %s\n",
                        hops, remotes, time_to_live,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_sync_taskcomm_from_local beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_sync_taskcomm_from_local end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_CVECTOR, LOC_API_0144);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        CVECTOR *mod_node_vec;

        mod_node_vec = cvector_new(0, MM_MOD_NODE, LOC_API_0145);
        cvector_push(report_vec, (void *)mod_node_vec);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_sync_taskcomm_from_local, CMPI_ERROR_MODI, hops, remotes, time_to_live, mod_node_vec);
    }
    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        CVECTOR *mod_node_vec;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        mod_node_vec = (CVECTOR *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        cvector_print(des_log, mod_node_vec, (CVECTOR_DATA_PRINT)mod_node_print);

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cvector_clean(mod_node_vec, (CVECTOR_DATA_CLEANER)mod_node_free, LOC_API_0146);
        cvector_free(mod_node_vec, LOC_API_0147);
    }

    cvector_free(report_vec, LOC_API_0148);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_sync_rank_load(CMD_PARA_VEC * param)
{
    UINT32 fr_tcid;
    UINT32 fr_rank;
    UINT32 to_tcid;
    UINT32 to_rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param   , 0, &fr_tcid);
    api_cmd_para_vec_get_uint32(param , 1, &fr_rank);
    api_cmd_para_vec_get_tcid(param   , 2, &to_tcid);
    api_cmd_para_vec_get_uint32(param , 3, &to_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "sync rank load from tcid %s rank %ld to tcid %s rank %ld\n",
                        c_word_to_ipv4(fr_tcid), fr_rank,
                        c_word_to_ipv4(to_tcid), to_rank
                        );

    mod_mgr = api_cmd_ui_gen_mod_mgr(to_tcid, to_rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_sync_rank_load beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_sync_rank_load end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_sync_rank_load, CMPI_ERROR_MODI, fr_tcid, fr_rank);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_sync_rank_load_to_all(CMD_PARA_VEC * param)
{
    UINT32 fr_tcid;
    UINT32 fr_rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param   , 0, &fr_tcid);
    api_cmd_para_vec_get_uint32(param , 1, &fr_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "sync rank load from tcid %s rank %ld to all\n",
                        c_word_to_ipv4(fr_tcid), fr_rank
                        );

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
    mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);
    mod_mgr_excl(CMPI_ANY_MON_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);

#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_sync_rank_load_to_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_sync_rank_load_to_all end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_sync_rank_load, CMPI_ERROR_MODI, fr_tcid, fr_rank);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_set_rank_load(CMD_PARA_VEC * param)
{
    UINT32 of_tcid;
    UINT32 of_rank;
    UINT32 on_tcid;
    UINT32 on_rank;

    UINT32 que_load;
    UINT32 obj_load;
    UINT32 cpu_load;
    UINT32 mem_load;
    UINT32 dsk_load;
    UINT32 net_load;

    CLOAD_STAT cload_stat;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param   , 0, &of_tcid);
    api_cmd_para_vec_get_uint32(param , 1, &of_rank);
    api_cmd_para_vec_get_uint32(param , 2, &que_load);
    api_cmd_para_vec_get_uint32(param , 3, &obj_load);
    api_cmd_para_vec_get_uint32(param , 4, &cpu_load);
    api_cmd_para_vec_get_uint32(param , 5, &mem_load);
    api_cmd_para_vec_get_uint32(param , 6, &dsk_load);
    api_cmd_para_vec_get_uint32(param , 7, &net_load);
    api_cmd_para_vec_get_tcid(param   , 8, &on_tcid);
    api_cmd_para_vec_get_uint32(param , 9, &on_rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "set rank load of tcid %s rank %ld as load que %ld obj %ld cpu %ld mem %ld dsk %ld net %ld on tcid %s rank %ld\n",
                        c_word_to_ipv4(of_tcid), of_rank,
                        que_load, obj_load, cpu_load, mem_load, dsk_load, net_load,
                        c_word_to_ipv4(on_tcid), on_rank
                        );

    CLOAD_STAT_QUE_LOAD(&cload_stat) = (UINT16)que_load;
    CLOAD_STAT_OBJ_LOAD(&cload_stat) = (UINT16)obj_load;
    CLOAD_STAT_CPU_LOAD(&cload_stat) = (UINT8 )cpu_load;
    CLOAD_STAT_MEM_LOAD(&cload_stat) = (UINT8 )mem_load;
    CLOAD_STAT_DSK_LOAD(&cload_stat) = (UINT8 )dsk_load;
    CLOAD_STAT_NET_LOAD(&cload_stat) = (UINT8 )net_load;

    mod_mgr = api_cmd_ui_gen_mod_mgr(on_tcid, on_rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_rank_load beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_rank_load end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_set_rank_load, CMPI_ERROR_MODI, of_tcid, of_rank, &cload_stat);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_set_rank_load_on_all(CMD_PARA_VEC * param)
{
    UINT32 of_tcid;
    UINT32 of_rank;

    UINT32 que_load;
    UINT32 obj_load;
    UINT32 cpu_load;
    UINT32 mem_load;
    UINT32 dsk_load;
    UINT32 net_load;

    CLOAD_STAT cload_stat;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param   , 0, &of_tcid);
    api_cmd_para_vec_get_uint32(param , 1, &of_rank);
    api_cmd_para_vec_get_uint32(param , 2, &que_load);
    api_cmd_para_vec_get_uint32(param , 3, &obj_load);
    api_cmd_para_vec_get_uint32(param , 4, &cpu_load);
    api_cmd_para_vec_get_uint32(param , 5, &mem_load);
    api_cmd_para_vec_get_uint32(param , 6, &dsk_load);
    api_cmd_para_vec_get_uint32(param , 7, &net_load);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "set rank load of tcid %s rank %ld as load que %ld obj %ld cpu %ld mem %ld dsk %ld net %ld on all\n",
                        c_word_to_ipv4(of_tcid), of_rank,
                        que_load, obj_load, cpu_load, mem_load, dsk_load, net_load
                        );

    CLOAD_STAT_QUE_LOAD(&cload_stat) = (UINT16)que_load;
    CLOAD_STAT_OBJ_LOAD(&cload_stat) = (UINT16)obj_load;
    CLOAD_STAT_CPU_LOAD(&cload_stat) = (UINT8 )cpu_load;
    CLOAD_STAT_MEM_LOAD(&cload_stat) = (UINT8 )mem_load;
    CLOAD_STAT_DSK_LOAD(&cload_stat) = (UINT8 )dsk_load;
    CLOAD_STAT_NET_LOAD(&cload_stat) = (UINT8 )net_load;

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
    mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);
    mod_mgr_excl(CMPI_ANY_MON_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);

#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_rank_load_on_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_set_rank_load_on_all end ----------------------------------\n");
    }
#endif

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_set_rank_load, CMPI_ERROR_MODI, of_tcid, of_rank, &cload_stat);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_add(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_name;
    UINT32   session_expire_nsec;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_name);
    api_cmd_para_vec_get_uint32(param , 1, &session_expire_nsec);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_uint32(param , 4, &modi);
    api_cmd_para_vec_get_cstring(param, 5, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session add name %s expire %ld on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_name),
                        session_expire_nsec,
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_add beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_add end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0295);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0296);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_add, CMPI_ERROR_MODI, session_name, session_expire_nsec);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0297);
    }

    cvector_free_no_lock(report_vec, LOC_API_0298);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_rmv_by_name(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_name;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_name);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_uint32(param , 2, &rank);
    api_cmd_para_vec_get_uint32(param , 3, &modi);
    api_cmd_para_vec_get_cstring(param, 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session rmv name %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_name),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_name beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_name end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0299);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0300);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_rmv_by_name, CMPI_ERROR_MODI, session_name);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0301);
    }

    cvector_free_no_lock(report_vec, LOC_API_0302);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_rmv_by_id(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    UINT32   session_id;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &session_id);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_uint32(param , 2, &rank);
    api_cmd_para_vec_get_uint32(param , 3, &modi);
    api_cmd_para_vec_get_cstring(param, 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session rmv id %ld on tcid %s rank %ld modi %ld at %s\n",
                        session_id,
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_id beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_id end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0303);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0304);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_rmv_by_id, CMPI_ERROR_MODI, session_id);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0305);
    }

    cvector_free_no_lock(report_vec, LOC_API_0306);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_rmv_by_name_regex(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_name;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_name);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_uint32(param , 2, &rank);
    api_cmd_para_vec_get_uint32(param , 3, &modi);
    api_cmd_para_vec_get_cstring(param, 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session rmv nameregex %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_name),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_name_regex beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_name_regex end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0307);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0308);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_rmv_by_name_regex, CMPI_ERROR_MODI, session_name);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0309);
    }

    cvector_free_no_lock(report_vec, LOC_API_0310);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_rmv_by_id_regex(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_id;/*session id string*/

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_id);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_uint32(param , 2, &rank);
    api_cmd_para_vec_get_uint32(param , 3, &modi);
    api_cmd_para_vec_get_cstring(param, 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session rmv idregex %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_id),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_id_regex beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_rmv_by_id_regex end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0311);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0312);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_rmv_by_id_regex, CMPI_ERROR_MODI, session_id);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0313);
    }

    cvector_free_no_lock(report_vec, LOC_API_0314);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_set_by_name(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_name;
    CSTRING *key;
    CSTRING *val;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    CBYTES val_cbytes;

    api_cmd_para_vec_get_cstring(param, 0, &session_name);
    api_cmd_para_vec_get_cstring(param, 1, &key);
    api_cmd_para_vec_get_cstring(param, 2, &val);
    api_cmd_para_vec_get_tcid(param   , 3, &tcid);
    api_cmd_para_vec_get_uint32(param , 4, &rank);
    api_cmd_para_vec_get_uint32(param , 5, &modi);
    api_cmd_para_vec_get_cstring(param, 6, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session set name %s key %s val %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_name),
                        (char *)cstring_get_str(key),
                        (char *)cstring_get_str(val),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_set_by_name beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_set_by_name end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0315);
    cbytes_init(&val_cbytes);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;
        alloc_static_mem(MM_UINT32, &ret, LOC_API_0316);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        cbytes_mount(&val_cbytes, cstring_get_len(val), cstring_get_str(val));
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_set_by_name, CMPI_ERROR_MODI, session_name, key, &val_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0317);
    }

    cvector_free_no_lock(report_vec, LOC_API_0318);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_set_by_id(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    UINT32   session_id;
    CSTRING *key;
    CSTRING *val;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    CBYTES     val_cbytes;

    api_cmd_para_vec_get_uint32(param , 0, &session_id);
    api_cmd_para_vec_get_cstring(param, 1, &key);
    api_cmd_para_vec_get_cstring(param, 2, &val);
    api_cmd_para_vec_get_tcid(param   , 3, &tcid);
    api_cmd_para_vec_get_uint32(param , 4, &rank);
    api_cmd_para_vec_get_uint32(param , 5, &modi);
    api_cmd_para_vec_get_cstring(param, 6, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session set id %ld key %s val %s on tcid %s rank %ld modi %ld at %s\n",
                        session_id,
                        (char *)cstring_get_str(key),
                        (char *)cstring_get_str(val),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_set_by_id beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_set_by_id end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0319);
    cbytes_init(&val_cbytes);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0320);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        cbytes_mount(&val_cbytes, cstring_get_len(val), cstring_get_str(val));
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_set_by_id, CMPI_ERROR_MODI, session_id, key, &val_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0321);
    }

    cvector_free_no_lock(report_vec, LOC_API_0322);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_get_by_name(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_name;
    CSTRING *key;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *csession_item_list_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_name);
    api_cmd_para_vec_get_cstring(param, 1, &key);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_uint32(param , 4, &modi);
    api_cmd_para_vec_get_cstring(param, 5, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session get name %s key %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_name),
                        (char *)cstring_get_str(key),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_name beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_name end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0323);
    csession_item_list_vec = cvector_new(0, MM_CLIST, LOC_API_0324);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;
        CLIST     *csession_item_list;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0325);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        csession_item_list = clist_new(MM_CSESSION_ITEM, LOC_API_0326);
        cvector_push_no_lock(csession_item_list_vec, (void *)csession_item_list);

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_get_by_name, CMPI_ERROR_MODI, session_name, key, csession_item_list);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;
        CLIST     *csession_item_list;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);
        csession_item_list = (CLIST *)cvector_get_no_lock(csession_item_list_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
            clist_print_level(des_log, csession_item_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_item_print);
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0327);

        cvector_set_no_lock(csession_item_list_vec, remote_mod_node_idx, NULL_PTR);
        clist_free(csession_item_list, LOC_API_0328);
    }

    cvector_free_no_lock(report_vec, LOC_API_0329);
    cvector_free_no_lock(csession_item_list_vec, LOC_API_0330);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_get_by_id(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    UINT32   session_id;
    CSTRING *key;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *csession_item_list_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_uint32(param , 0, &session_id);
    api_cmd_para_vec_get_cstring(param, 1, &key);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_uint32(param , 4, &modi);
    api_cmd_para_vec_get_cstring(param, 5, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session get id %ld key %s on tcid %s rank %ld modi %ld at %s\n",
                        session_id,
                        (char *)cstring_get_str(key),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_id beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_id end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0331);
    csession_item_list_vec = cvector_new(0, MM_CLIST, LOC_API_0332);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;
        CLIST     *csession_item_list;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0333);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        csession_item_list = clist_new(MM_CSESSION_ITEM, LOC_API_0334);
        cvector_push_no_lock(csession_item_list_vec, (void *)csession_item_list);

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_get_by_id, CMPI_ERROR_MODI, session_id, key, csession_item_list);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;
        CLIST     *csession_item_list;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);
        csession_item_list = (CLIST *)cvector_get_no_lock(csession_item_list_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
            clist_print_level(des_log, csession_item_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_item_print);
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0335);

        cvector_set_no_lock(csession_item_list_vec, remote_mod_node_idx, NULL_PTR);
        clist_free(csession_item_list, LOC_API_0336);
    }

    cvector_free_no_lock(report_vec, LOC_API_0337);
    cvector_free_no_lock(csession_item_list_vec, LOC_API_0338);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_csession_get_by_name_regex(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_name;
    CSTRING *key;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *csession_node_list_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_name);
    api_cmd_para_vec_get_cstring(param, 1, &key);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_uint32(param , 4, &modi);
    api_cmd_para_vec_get_cstring(param, 5, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session get nameregex %s key %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_name),
                        (char *)cstring_get_str(key),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_name_regex beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_name_regex end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0339);
    csession_node_list_vec = cvector_new(0, MM_CLIST, LOC_API_0340);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;
        CLIST     *csession_node_list;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0341);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        csession_node_list = clist_new(MM_CSESSION_NODE, LOC_API_0342);
        cvector_push_no_lock(csession_node_list_vec, (void *)csession_node_list);

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_get_by_name_regex, CMPI_ERROR_MODI, session_name, key, csession_node_list);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;
        CLIST     *csession_node_list;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);
        csession_node_list = (CLIST *)cvector_get_no_lock(csession_node_list_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
            clist_print_level(des_log, csession_node_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_node_print);
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0343);

        cvector_set_no_lock(csession_node_list_vec, remote_mod_node_idx, NULL_PTR);
        clist_free(csession_node_list, LOC_API_0344);
    }

    cvector_free_no_lock(report_vec, LOC_API_0345);
    cvector_free_no_lock(csession_node_list_vec, LOC_API_0346);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csession_get_by_id_regex(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;
    CSTRING *session_id;/*regex string*/
    CSTRING *key;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *csession_node_list_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &session_id);
    api_cmd_para_vec_get_cstring(param, 1, &key);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_uint32(param , 3, &rank);
    api_cmd_para_vec_get_uint32(param , 4, &modi);
    api_cmd_para_vec_get_cstring(param, 5, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session get id regex %s key %s on tcid %s rank %ld modi %ld at %s\n",
                        (char *)cstring_get_str(session_id),
                        (char *)cstring_get_str(key),
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_id_regex beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_get_by_id_regex end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0347);
    csession_node_list_vec = cvector_new(0, MM_CLIST, LOC_API_0348);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32    *ret;
        CLIST     *csession_node_list;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0349);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        csession_node_list = clist_new(MM_CSESSION_NODE, LOC_API_0350);
        cvector_push_no_lock(csession_node_list_vec, (void *)csession_node_list);

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_csession_get_by_id_regex, CMPI_ERROR_MODI, session_id, key, csession_node_list);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE  *mod_node;
        UINT32    *ret;
        CLIST     *csession_node_list;

        mod_node  = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);
        csession_node_list = (CLIST *)cvector_get_no_lock(csession_node_list_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
            clist_print_level(des_log, csession_node_list, 0, (CLIST_DATA_LEVEL_PRINT)csession_node_print);
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0351);

        cvector_set_no_lock(csession_node_list_vec, remote_mod_node_idx, NULL_PTR);
        clist_free(csession_node_list, LOC_API_0352);
    }

    cvector_free_no_lock(report_vec, LOC_API_0353);
    cvector_free_no_lock(csession_node_list_vec, LOC_API_0354);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_csession_show(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   rank;
    UINT32   modi;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param   , 0, &tcid);
    api_cmd_para_vec_get_uint32(param , 1, &rank);
    api_cmd_para_vec_get_uint32(param , 2, &modi);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "session show on tcid %s rank %ld modi %ld at %s\n",
                        c_word_to_ipv4(tcid),
                        rank,
                        modi,
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, modi);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_show beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csession_show end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0355);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_csession_show, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free_no_lock(report_vec, LOC_API_0356);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_enable_task_brd(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enable task brd on tcid %s rank %ld\n", c_word_to_ipv4((tcid)), rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_task_brd beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_task_brd end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_enable_task_brd, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_enable_all_task_brd(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "enable task brd on all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
    mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);
    mod_mgr_excl(CMPI_ANY_MON_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);

#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_all_task_brd beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_enable_all_task_brd end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_enable_task_brd, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_disable_task_brd(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    UINT32 rank;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_uint32(param, 1, &rank);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "disable task brd on tcid %s rank %ld\n", c_word_to_ipv4((tcid)), rank);

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, rank, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_task_brd beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_task_brd end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_disable_task_brd, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_disable_all_task_brd(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "disable task brd on all\n");

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
    mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);
    mod_mgr_excl(CMPI_ANY_MON_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);

#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_all_task_brd beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_disable_all_task_brd end ----------------------------------\n");
    }
#endif
#if 1
    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_disable_task_brd, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_exec_download(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *fname;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *fcontent_vec;

    LOG *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &fname);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "exec download %s on tcid %s at %s\n",
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_download beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_download end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0358);
    fcontent_vec = cvector_new(0, MM_CBYTES, LOC_API_0359);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;
        CBYTES *cbytes;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0360);
        cbytes = cbytes_new(0);

        cvector_push(report_vec, (void *)ret);
        cvector_push(fcontent_vec, (void *)cbytes);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_download, CMPI_ERROR_MODI, fname, cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32 *ret;
        CBYTES *cbytes;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret      = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        cbytes   = (CBYTES *)cvector_get(fcontent_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n%.*s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                             cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));

        }
        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cvector_set(fcontent_vec, remote_mod_node_idx, NULL_PTR);

        free_static_mem(MM_UINT32, ret, LOC_API_0361);
        cbytes_free(cbytes);
    }

    cvector_free(report_vec, LOC_API_0362);
    cvector_free(fcontent_vec, LOC_API_0363);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_exec_download_all(CMD_PARA_VEC * param)
{
    CSTRING *fname;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *fcontent_vec;

    LOG *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &fname);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "exec download %s on all at %s\n",
                        (char *)cstring_get_str(fname),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_ANY_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_download_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_download_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0364);
    fcontent_vec = cvector_new(0, MM_CBYTES, LOC_API_0365);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;
        CBYTES *cbytes;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0366);
        cbytes = cbytes_new(0);

        cvector_push(report_vec, (void *)ret);
        cvector_push(fcontent_vec, (void *)cbytes);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_download, CMPI_ERROR_MODI, fname, cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32 *ret;
        CBYTES *cbytes;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret      = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        cbytes   = (CBYTES *)cvector_get(fcontent_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n%.*s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                             cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));

        }
        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cvector_set(fcontent_vec, remote_mod_node_idx, NULL_PTR);

        free_static_mem(MM_UINT32, ret, LOC_API_0367);
        cbytes_free(cbytes);
    }

    cvector_free(report_vec, LOC_API_0368);
    cvector_free(fcontent_vec, LOC_API_0369);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_exec_upload(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *fname;
    CSTRING *fcontent;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *fcontent_vec;

    LOG *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &fname);
    api_cmd_para_vec_get_cstring(param, 1, &fcontent);
    api_cmd_para_vec_get_tcid(param   , 2, &tcid);
    api_cmd_para_vec_get_cstring(param, 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "exec upload %s with %s on tcid %s at %s\n",
                        (char *)cstring_get_str(fname),
                        (char *)cstring_get_str(fcontent),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_upload beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_upload end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0370);
    fcontent_vec = cvector_new(0, MM_CBYTES, LOC_API_0371);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;
        CBYTES *cbytes;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0372);
        cbytes = cbytes_new(0);
        cbytes_mount(cbytes, cstring_get_len(fcontent), cstring_get_str(fcontent));

        cvector_push(report_vec, (void *)ret);
        cvector_push(fcontent_vec, (void *)cbytes);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_upload, CMPI_ERROR_MODI, fname, cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32 *ret;
        CBYTES *cbytes;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret      = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        cbytes   = (CBYTES *)cvector_get(fcontent_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n%.*s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                             cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));

        }
        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cvector_set(fcontent_vec, remote_mod_node_idx, NULL_PTR);

        free_static_mem(MM_UINT32, ret, LOC_API_0373);

        cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
        cbytes_free(cbytes);
    }

    cvector_free(report_vec, LOC_API_0374);
    cvector_free(fcontent_vec, LOC_API_0375);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_exec_upload_all(CMD_PARA_VEC * param)
{
    CSTRING *fname;
    CSTRING *fcontent;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    CVECTOR *fcontent_vec;

    LOG *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &fname);
    api_cmd_para_vec_get_cstring(param, 1, &fcontent);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "exec upload %s with %s on all at %s\n",
                        (char *)cstring_get_str(fname),
                        (char *)cstring_get_str(fcontent),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_upload_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_upload_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0376);
    fcontent_vec = cvector_new(0, MM_CBYTES, LOC_API_0377);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;
        CBYTES *cbytes;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0378);
        cbytes = cbytes_new(0);
        cbytes_mount(cbytes, cstring_get_len(fcontent), cstring_get_str(fcontent));

        cvector_push(report_vec, (void *)ret);
        cvector_push(fcontent_vec, (void *)cbytes);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_upload, CMPI_ERROR_MODI, fname, cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        UINT32 *ret;
        CBYTES *cbytes;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret      = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);
        cbytes   = (CBYTES *)cvector_get(fcontent_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n%.*s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                             cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));

        }
        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cvector_set(fcontent_vec, remote_mod_node_idx, NULL_PTR);

        free_static_mem(MM_UINT32, ret, LOC_API_0379);

        cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
        cbytes_free(cbytes);
    }

    cvector_free(report_vec, LOC_API_0380);
    cvector_free(fcontent_vec, LOC_API_0381);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_exec_shell(CMD_PARA_VEC * param)
{
    UINT32 tcid;

    CSTRING *cmd_line;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG     *des_log;
    EC_BOOL  ret;

    api_cmd_para_vec_get_cstring(param, 0, &cmd_line);
    api_cmd_para_vec_get_tcid(param   , 1, &tcid);
    api_cmd_para_vec_get_cstring(param, 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "exec shell '%s' on tcid %s where %s\n",
                        (char *)cstring_get_str(cmd_line),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_shell beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_shell end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_CBYTES, LOC_API_0382);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        CBYTES *cbytes;

        cbytes = cbytes_new(0);

        cvector_push(report_vec, (void *)cbytes);
        task_pos_inc(task_mgr, remote_mod_node_idx, &ret, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        CBYTES *cbytes;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        cbytes = (CBYTES *)cvector_get(report_vec, remote_mod_node_idx);

        if(0 == cbytes_len(cbytes))
        {
            sys_log(des_log, "[rank_%s_%ld] %s\n(null)\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                            (char *)cstring_get_str(cmd_line));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] %s\n%.*s\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                            (char *)cstring_get_str(cmd_line),
                            cbytes_len(cbytes), cbytes_buf(cbytes));
        }
        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cbytes_free(cbytes);
    }

    cvector_free(report_vec, LOC_API_0383);
    mod_mgr_free(mod_mgr);
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_exec_shell_all(CMD_PARA_VEC * param)
{
    CSTRING *cmd_line;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;
    EC_BOOL ret;

    api_cmd_para_vec_get_cstring(param, 0, &cmd_line);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "exec shell '%s' on all at %s\n",
                        (char *)cstring_get_str(cmd_line),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_shell_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_exec_shell_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_CBYTES, LOC_API_0384);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        CBYTES *cbytes;

        cbytes = cbytes_new(0);

        cvector_push(report_vec, (void *)cbytes);
        task_pos_inc(task_mgr, remote_mod_node_idx, &ret, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        CBYTES *cbytes;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        cbytes = (CBYTES *)cvector_get(report_vec, remote_mod_node_idx);

        if(0 == cbytes_len(cbytes))
        {
            sys_log(des_log, "[rank_%s_%ld] %s\n(null)\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                            (char *)cstring_get_str(cmd_line));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld] %s\n%.*s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node),
                            (char *)cstring_get_str(cmd_line),
                            cbytes_len(cbytes), cbytes_buf(cbytes));
        }
        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        cbytes_free(cbytes);
    }

    cvector_free(report_vec, LOC_API_0385);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_version(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show version on tcid %s at %s\n", c_word_to_ipv4(tcid), (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_version beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_version end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0386);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_version, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0387);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_version_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show version on all at %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_version_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_version_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0388);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();
        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_version, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0389);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_vendor(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show vendor on tcid %s at %s\n", c_word_to_ipv4(tcid), (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_vendor beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_vendor end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0390);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();

        cvector_push(report_vec, (void *)log);
        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_vendor, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0391);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_show_vendor_all(CMD_PARA_VEC * param)
{
    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;
    CSTRING *where;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;
    LOG   *des_log;

    api_cmd_para_vec_get_cstring(param, 0, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "show vendor on all at %s\n", (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(CMPI_ANY_TCID, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_vendor_all beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_show_vendor_all end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_LOG, LOC_API_0392);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        LOG *log;

        log = log_cstr_open();
        cvector_push(report_vec, (void *)log);

        task_pos_inc(task_mgr, remote_mod_node_idx, NULL_PTR, FI_super_show_vendor, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
        LOG *log;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        log = (LOG *)cvector_get(report_vec, remote_mod_node_idx);

        sys_log(des_log, "[rank_%s_%ld]\n%s", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node), (char *)cstring_get_str(LOG_CSTR(log)));

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        log_cstr_close(log);
    }

    cvector_free(report_vec, LOC_API_0393);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_start_mcast_udp_server(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "start udp server on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_start_mcast_udp_server beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_start_mcast_udp_server end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0394);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0395);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_start_mcast_udp_server, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
         UINT32 *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);\

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0396);
    }

    cvector_free(report_vec, LOC_API_0397);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_stop_mcast_udp_server(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "stop udp server on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_stop_mcast_udp_server beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_stop_mcast_udp_server end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0398);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0399);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_stop_mcast_udp_server, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
         UINT32 *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get_no_lock(report_vec, remote_mod_node_idx);

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][SUCC]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][FAIL]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set_no_lock(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0400);
    }

    cvector_free(report_vec, LOC_API_0401);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_status_mcast_udp_server(CMD_PARA_VEC * param)
{
    UINT32 tcid;
    CSTRING *where;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    UINT32 remote_mod_node_num;
    UINT32 remote_mod_node_idx;

    CVECTOR *report_vec;

    LOG *des_log;

    api_cmd_para_vec_get_tcid(param, 0, &tcid);
    api_cmd_para_vec_get_cstring(param, 1, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "status udp server on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = api_cmd_ui_gen_mod_mgr(tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*super_md_id = 0*/
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_status_mcast_udp_server beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_status_mcast_udp_server end ----------------------------------\n");
    }
#endif

    report_vec = cvector_new(0, MM_UINT32, LOC_API_0402);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        UINT32 *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_API_0403);
        cvector_push_no_lock(report_vec, (void *)ret);
        (*ret) = EC_FALSE;

        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_super_status_mcast_udp_server, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        MOD_NODE *mod_node;
         UINT32 *ret;

        mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_idx);
        ret = (UINT32 *)cvector_get(report_vec, remote_mod_node_idx);\

        if(EC_TRUE == (*ret))
        {
            sys_log(des_log, "[rank_%s_%ld][ACTIVE]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }
        else
        {
            sys_log(des_log, "[rank_%s_%ld][INACTIVE]\n", MOD_NODE_TCID_STR(mod_node),MOD_NODE_RANK(mod_node));
        }

        cvector_set(report_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_API_0404);
    }

    cvector_free(report_vec, LOC_API_0405);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

#if 1
EC_BOOL api_cmd_ui_crfs_create_npp(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_model;
    UINT32   crfsnp_max_num;
    UINT32   crfsnp_2nd_chash_algo_id;
    CSTRING *crfsnp_db_root_dir;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &crfsnp_model);
    api_cmd_para_vec_get_uint32(param  , 2, &crfsnp_max_num);
    api_cmd_para_vec_get_uint32(param  , 3, &crfsnp_2nd_chash_algo_id);
    api_cmd_para_vec_get_cstring(param , 4, &crfsnp_db_root_dir);
    api_cmd_para_vec_get_tcid(param    , 5, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 6, &where);

    /*hsrfs <id> create np model <model> max num <np mum> with hash algo <id> and root <root dir> on tcid <tcid> at <where>*/
    /*hsrfs %n create np model %n max num %n with hash algo %n and root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_create_npp: hsrfs %ld create np model %ld max num %ld with hash algo %ld and root %s on tcid %s at %s\n",
                        crfs_modi,
                        crfsnp_model,
                        crfsnp_max_num,
                        crfsnp_2nd_chash_algo_id,
                        (char *)cstring_get_str(crfsnp_db_root_dir),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_create_npp, CMPI_ERROR_MODI,
             crfsnp_model, crfsnp_max_num, crfsnp_2nd_chash_algo_id, crfsnp_db_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfs %ld create np model %u max num %u with hash algo %u and root %s on tcid %s successfully\n",
                        crfs_modi,
                        crfsnp_model,
                        crfsnp_max_num,
                        crfsnp_2nd_chash_algo_id,
                        (char *)cstring_get_str(crfsnp_db_root_dir),
                        c_word_to_ipv4(crfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfs %ld create np model %u max num %u with hash algo %u and root %s on tcid %s failed\n",
                        crfs_modi,
                        crfsnp_model,
                        crfsnp_max_num,
                        crfsnp_2nd_chash_algo_id,
                        (char *)cstring_get_str(crfsnp_db_root_dir),
                        c_word_to_ipv4(crfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_create_dn(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *crfsnp_dn_root_dir;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &crfsnp_dn_root_dir);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> create dn with root <root dir> on tcid <tcid> at <where>*/
    /*hsrfs %n create dn with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_create_dn: hsrfs %ld create dn with root %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(crfsnp_dn_root_dir),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_create_dn, CMPI_ERROR_MODI, crfsnp_dn_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfs %ld create dn with root %s on tcid %s successfully\n",
                        crfs_modi,
                        (char *)cstring_get_str(crfsnp_dn_root_dir),
                        c_word_to_ipv4(crfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfs %ld create dn with root %s on tcid %s failed\n",
                        crfs_modi,
                        (char *)cstring_get_str(crfsnp_dn_root_dir),
                        c_word_to_ipv4(crfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_add_disk(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   disk_no;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> add disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfs %n add disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_add_disk: hsrfs %ld add disk %ld on tcid %s at %s\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_add_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfs %ld add disk %ld on tcid %s successfully\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfs %ld add disk %ld on tcid %s failed\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_del_disk(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   disk_no;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> del disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfs %n del disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_del_disk: hsrfs %ld del disk %ld on tcid %s at %s\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_del_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfs %ld del disk %ld on tcid %s successfully\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfs %ld del disk %ld on tcid %s failed\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_mount_disk(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   disk_no;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> mount disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfs %n mount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_mount_disk: hsrfs %ld mount disk %ld on tcid %s at %s\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_mount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfs %ld mount disk %ld on tcid %s successfully\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfs %ld mount disk %ld on tcid %s failed\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_umount_disk(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   disk_no;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> umount disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfs %n umount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_umount_disk: hsrfs %ld umount disk %ld on tcid %s at %s\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_umount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfs %ld umount disk %ld on tcid %s successfully\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfs %ld umount disk %ld on tcid %s failed\n",
                        crfs_modi,
                        disk_no,
                        c_word_to_ipv4(crfsnp_tcid));
    }

    return (EC_TRUE);
}
EC_BOOL api_cmd_ui_crfs_open(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *crfs_root_dir;
    UINT32   crfsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &crfs_root_dir);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);

    /*hsrfs <id> open from root <dir> on tcid <tcid>*/
    /*hsrfs %n open from root %s on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_open: hsrfs %ld open from root %s on tcid %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(crfs_root_dir),
                        c_word_to_ipv4(crfsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(crfsnp_tcid, CMPI_CRFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, crfs_modi);

    task_act(mod_mgr_def, NULL_PTR, TASK_DEFAULT_LIVE, (UINT32)1, LOAD_BALANCING_LOOP, TASK_PRIO_NORMAL,
             FI_crfs_start, crfs_root_dir);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_close(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);

    /*hsrfs <id> close on tcid <tcid>*/
    /*hsrfs %n close on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_close: hsrfs %ld close on tcid %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(crfsnp_tcid, CMPI_CRFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, crfs_modi);

    task_dea(mod_mgr_def, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_crfs_end, CMPI_ERROR_MODI);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_read(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *file_name;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &file_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> read file <name> on tcid <tcid> at <where>*/
    /*hsrfs %n read file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_read: hsrfs %ld read file %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_read, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_crfs_read: read %s result: \n%.*s\n",
                          (char *)cstring_get_str(file_name),
                          cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_crfs_read: read %s failed\n", (char *)cstring_get_str(file_name));
    }

    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_write(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *file_name;
    CSTRING *file_content;
//    UINT32   expire_nsec;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &file_name);
    api_cmd_para_vec_get_cstring(param , 2, &file_content);
    //api_cmd_para_vec_get_uint32(param  , 3, &expire_nsec);
    api_cmd_para_vec_get_tcid(param    , 3, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*hsrfs <id> write file <name> with content <string> on tcid <tcid> at <where>*/
    /*hsrfs %n write file %s with content %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_write: hsrfs %ld write file %s with content %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(file_name),
                        (char *)cstring_get_str(file_content),
                        /*expire_nsec,*/
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    cbytes_mount(cbytes,cstring_get_len(file_content), cstring_get_str(file_content));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_write, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] file name %s\n", (char *)cstring_get_str(file_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] file name %s\n", (char *)cstring_get_str(file_name));
    }

    cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_mkdir(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path_name;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> mkdir <path> on tcid <tcid> at <where>*/
    /*hsrfs %n mkdir %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_mkdir: hsrfs %ld mkdir %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_mkdir, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] mkdir %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] mkdir %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_search(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path_name;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> search <path> on tcid <tcid> at <where>*/
    /*hsrfs %n search %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_search: hsrfs %ld search %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_search, CMPI_ERROR_MODI, path_name, (UINT32)CRFSNP_ITEM_FILE_IS_ANY);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_count_file_num(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path_name;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    UINT32   file_num;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> count file num of <path> on tcid <tcid> at <where>*/
    /*hsrfs %n count file num of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_count_file_num: hsrfs %ld count file num of path %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_file_num, CMPI_ERROR_MODI, path_name, &file_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file num of path %s: %ld\n", (char *)cstring_get_str(path_name), file_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file num of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_count_file_size(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path_name;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    uint64_t  file_size;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> count file size of <path> on tcid <tcid> at <where>*/
    /*hsrfs %n count file size of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_file_size: hsrfs %ld count file size of path %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_file_size, CMPI_ERROR_MODI, path_name, &file_size);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file size of path %s: %"PRId64"\n", (char *)cstring_get_str(path_name), file_size);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file size of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qfile(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *file_name;
    CSTRING *where;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CRFSNP_ITEM *crfsnp_item;
    CRFSNP_KEY  *crfsnp_key;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &file_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qfile %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qfile beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qfile end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;
    crfsnp_item = crfsnp_item_new();
    ASSERT(NULL_PTR != crfsnp_item);

    crfsnp_key = crfsnp_key_new();
    ASSERT(NULL_PTR != crfsnp_key);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qfile, CMPI_ERROR_MODI, file_name, crfsnp_item, crfsnp_key);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        crfsnp_item_print(des_log, crfsnp_item);
        crfsnp_key_print(des_log, crfsnp_key);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    crfsnp_item_free(crfsnp_item);
    crfsnp_key_free(crfsnp_key);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qdir(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *dir_name;
    CSTRING *where;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CRFSNP_ITEM *crfsnp_item;
    CRFSNP_KEY  *crfsnp_key;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &dir_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qdir %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(dir_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qdir beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qdir end ----------------------------------\n");
    }
#endif

    crfsnp_item = crfsnp_item_new();
    ASSERT(NULL_PTR != crfsnp_item);

    crfsnp_key = crfsnp_key_new();
    ASSERT(NULL_PTR != crfsnp_key);

    ret = EC_FALSE;

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qdir, CMPI_ERROR_MODI, dir_name, crfsnp_item, crfsnp_key);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC]\n");
        crfsnp_item_print(des_log, crfsnp_item);
        crfsnp_key_print(des_log, crfsnp_key);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    crfsnp_item_free(crfsnp_item);
    crfsnp_key_free(crfsnp_key);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qlist_path_of_np(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   crfsnp_id;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *path_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_uint32(param  , 2, &crfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 3, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qlist %s full of np %ld on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path),
                        crfsnp_id,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_path_of_np beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_path_of_np end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0406);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qlist_path_of_np, CMPI_ERROR_MODI, path, crfsnp_id, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }

    cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0407);
    cvector_free(path_cstr_vec, LOC_API_0408);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qlist_seg_of_np(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   crfsnp_id;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *seg_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_uint32(param  , 2, &crfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 3, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qlist %s short of np %ld on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path),
                        crfsnp_id,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_seg_of_np beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_seg_of_np end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    seg_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0409);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qlist_seg_of_np, CMPI_ERROR_MODI, path, crfsnp_id, seg_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }

    cvector_clean(seg_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0410);
    cvector_free(seg_cstr_vec, LOC_API_0411);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qlist_path(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *path_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qlist %s full on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_path beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_path end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0412);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qlist_path, CMPI_ERROR_MODI, path, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }

    cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0413);
    cvector_free(path_cstr_vec, LOC_API_0414);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qlist_seg(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *seg_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qlist %s short on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_seg beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_seg end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    seg_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0415);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qlist_seg, CMPI_ERROR_MODI, path, seg_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }

    cvector_clean(seg_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0416);
    cvector_free(seg_cstr_vec, LOC_API_0417);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qlist_tree_of_np(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   crfsnp_id;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *tree_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_uint32(param  , 2, &crfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 3, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qlist %s tree of np %ld on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path),
                        crfsnp_id,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_tree_of_np beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_tree_of_np end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    tree_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0418);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qlist_tree_of_np, CMPI_ERROR_MODI, crfsnp_id, path, tree_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(tree_cstr_vec); pos ++)
        {
            CSTRING *tree_cstr;

            tree_cstr = (CSTRING *)cvector_get(tree_cstr_vec, pos);
            if(NULL_PTR == tree_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(tree_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(tree_cstr_vec); pos ++)
        {
            CSTRING *tree_cstr;

            tree_cstr = (CSTRING *)cvector_get(tree_cstr_vec, pos);
            if(NULL_PTR == tree_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(tree_cstr));
        }
    }

    cvector_clean(tree_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0419);
    cvector_free(tree_cstr_vec, LOC_API_0420);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_qlist_tree(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   crfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *path_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfs %ld qlist %s tree on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfsnp_tcid, CMPI_ANY_COMM, CMPI_CRFS_RANK, crfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_tree beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfs_qlist_tree end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0421);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfsnp_tcid, &ret, FI_crfs_qlist_tree, CMPI_ERROR_MODI, path, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }

    cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0422);
    cvector_free(path_cstr_vec, LOC_API_0423);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_delete_file(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *fname;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &fname);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> delete file <name> on tcid <tcid> at <where>*/
    /*hsrfs %n delete file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_delete_file: hsrfs %ld delete file %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_delete_file, CMPI_ERROR_MODI, fname);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete file %s\n", (char *)cstring_get_str(fname));
        sys_log(LOGCONSOLE, "[SUCC] delete file %s\n", (char *)cstring_get_str(fname));
        if(des_log == LOGCONSOLE)
        {
            sys_log(LOGCONSOLE, "[SUCC] des_log is CONSOLE\n");
        }
        else
        {
            sys_log(LOGCONSOLE, "[SUCC] des_log is NOT CONSOLE\n");
        }
    }
    else
    {
        sys_log(des_log, "[FAIL] delete file %s\n", (char *)cstring_get_str(fname));
        sys_log(LOGCONSOLE, "[FAIL] delete file %s\n", (char *)cstring_get_str(fname));
        if(des_log == LOGCONSOLE)
        {
            sys_log(LOGCONSOLE, "[FAIL] des_log is CONSOLE\n");
        }
        else
        {
            sys_log(LOGCONSOLE, "[FAIL] des_log is NOT CONSOLE\n");
        }
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_delete_dir(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *dname;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    EC_BOOL   is_root_dir;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &dname);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> delete dir <name> on tcid <tcid> at <where>*/
    /*hsrfs %n delete dir %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_delete_dir: hsrfs %ld delete dir %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(dname),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;


    des_log = api_cmd_ui_get_log(where);

    ret = EC_FALSE;

    /* ensure the dir to delete is NOT root dir / */
    is_root_dir = cstring_is_str((const CSTRING *)dname, (const UINT8 *)"/");
    if(EC_FALSE == is_root_dir)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_delete_dir, CMPI_ERROR_MODI, dname);
    }
    else
    {
        sys_log(des_log, "[ERRO] can NOT use this interface to delete root dir %s \n", (char *)cstring_get_str(dname));
        //sys_log(des_log, "[WARN] to delete root dir, use command: hsrfs <id> delete root dir / on tcid <tcid> at <console|log>\n");
    }

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete dir %s\n", (char *)cstring_get_str(dname));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete dir %s\n", (char *)cstring_get_str(dname));
    }

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_crfs_delete_root_dir(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *dname;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    EC_BOOL   is_root_dir;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &dname);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_delete_root_dir: hsrfs %ld delete root dir %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(dname),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;


    des_log = api_cmd_ui_get_log(where);

    ret = EC_FALSE;

    /* ensure the dir to delete is root dir / */
    is_root_dir = cstring_is_str((const CSTRING *)dname, (const UINT8 *)"/");
    if(EC_TRUE == is_root_dir)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_delete_dir, CMPI_ERROR_MODI, dname);
    }
    else
    {
        sys_log(des_log, "[ERRO] the dir %s to delete is not root dir / \n", (char *)cstring_get_str(dname));
    }

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete root dir %s\n", (char *)cstring_get_str(dname));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete dir %s\n", (char *)cstring_get_str(dname));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_delete_path(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *path_name;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs delete path <name> on tcid <tcid> at <where>*/
    /*hsrfs delete path %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_delete_path: hsrfs %ld delete path %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_delete, CMPI_ERROR_MODI, path_name, (UINT32)CRFSNP_ITEM_FILE_IS_ANY);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete path %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_recycle(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;
    UINT32     complete_num;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> recycle on tcid <tcid> at <where>*/
    /*hsrfs %n recycle on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_recycle: hsrfs %ld recycle on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_recycle, CMPI_ERROR_MODI, CRFS_RECYCLE_MAX_NUM, &complete_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] recycle completion num %ld\n", complete_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] recycle\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_retire(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   max_retire_num;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;
    UINT32     complete_retire_num;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &max_retire_num);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> retire max <num> files on tcid <tcid> at <where>*/
    /*hsrfs %n retire max %n files on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_retire: hsrfs %ld retire max %ld files on tcid %s at %s\n",
                        crfs_modi,
                        max_retire_num,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    complete_retire_num = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_retire, CMPI_ERROR_MODI, max_retire_num, &complete_retire_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] retire %ld files\n", complete_retire_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] retire %ld files\n", complete_retire_num);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_flush(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> flush on tcid <tcid> at <where>*/
    /*hsrfs %n flush on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_flush: hsrfs %ld flush on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_flush, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] flush\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] flush\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_flush_npp(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> flush npp on tcid <tcid> at <where>*/
    /*hsrfs %n flush on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_flush_npp: hsrfs %ld flush npp on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_flush_npp, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] flush npp\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] flush npp\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_flush_dn(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> flush dn on tcid <tcid> at <where>*/
    /*hsrfs %n flush on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_flush_dn: hsrfs %ld flush dn on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_flush_dn, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] flush dn\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] flush dn\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_npp_lru_list(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show npp lru on tcid <tcid> at <where>*/
    /*hsrfs %n show npp lru on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_npp_lru_list: hsrfs %ld show npp lru on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_npp_lru_list, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_npp_del_list(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show npp del on tcid <tcid> at <where>*/
    /*hsrfs %n show npp del on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_npp_del_list: hsrfs %ld show npp del on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_npp_del_list, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_npp(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show npp on tcid <tcid> at <where>*/
    /*hsrfs %n show npp on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_npp: hsrfs %ld show npp on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_npp, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_dn(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show dn on tcid <tcid> at <where>*/
    /*hsrfs %n show dn on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_dn: hsrfs %ld show dn on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_dn, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_cached_np_lru_list(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show cached np lru on tcid <tcid> at <where>*/
    /*hsrfs %n show cached np lru on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_cached_np_lru_list: hsrfs %ld show cached np lru on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_cached_np_lru_list, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_cached_np_del_list(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show cached np del on tcid <tcid> at <where>*/
    /*hsrfs %n show cached np del on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_cached_np_del_list: hsrfs %ld show cached np del on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_cached_np_del_list, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_cached_np(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show cached np on tcid <tcid> at <where>*/
    /*hsrfs %n show cached np on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_cached_np: hsrfs %ld show cached np on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_cached_np, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_specific_np_lru_list(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_id;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &crfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> show specific np <id> lru on tcid <tcid> at <where>*/
    /*hsrfs %n show specific np %n lru on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_specific_np_lru_list: hsrfs %ld show specific np %ld lru on tcid %s at %s\n",
                        crfs_modi,
                        crfsnp_id,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_specific_np_lru_list, CMPI_ERROR_MODI, crfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(crfsnp_tcid),
                           CMPI_CRFS_RANK,
                           crfsnp_id,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(crfsnp_tcid),
                          CMPI_CRFS_RANK, crfsnp_id,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_specific_np_del_list(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_id;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &crfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> show specific np <id> del on tcid <tcid> at <where>*/
    /*hsrfs %n show specific np %n del on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_specific_np_del_list: hsrfs %ld show specific np %ld del on tcid %s at %s\n",
                        crfs_modi,
                        crfsnp_id,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_specific_np_del_list, CMPI_ERROR_MODI, crfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(crfsnp_tcid),
                           CMPI_CRFS_RANK,
                           crfsnp_id,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(crfsnp_tcid),
                          CMPI_CRFS_RANK, crfsnp_id,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_specific_np(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_id;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &crfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> show specific np <id> on tcid <tcid> at <where>*/
    /*hsrfs %n show specific np %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_specific_np: hsrfs %ld show specific np %ld on tcid %s at %s\n",
                        crfs_modi,
                        crfsnp_id,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_show_specific_np, CMPI_ERROR_MODI, crfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(crfsnp_tcid),
                           CMPI_CRFS_RANK,
                           crfsnp_id,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(crfsnp_tcid),
                          CMPI_CRFS_RANK, crfsnp_id,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_show_locked_files(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfs <id> show locked files on tcid <tcid> at <console|log>*/
    /*hsrfs %n show locked files on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_show_locked_files: hsrfs %ld locked files on tcid %s at %s\n",
                        crfs_modi,
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             NULL_PTR,
             FI_crfs_locked_files_print, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    sys_log(des_log, "[rank_%s_%ld][SUCC] \n%s",
                       c_word_to_ipv4(crfsnp_tcid),
                       CMPI_CRFS_RANK,
                       (char *)cstring_get_str(LOG_CSTR(log)));
    log_cstr_close(log);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfs_md5sum(CMD_PARA_VEC * param)
{
    UINT32   crfs_modi;
    CSTRING *fname;
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;
    CMD5_DIGEST md5sum;

    api_cmd_para_vec_get_uint32(param  , 0, &crfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &fname);
    api_cmd_para_vec_get_tcid(param    , 2, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfs <id> md5sum file <name> on tcid <tcid> at <where>*/
    /*hsrfs %n md5sum file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfs_md5sum: hsrfs %ld md5sum file %s on tcid %s at %s\n",
                        crfs_modi,
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_file_md5sum, CMPI_ERROR_MODI, fname, &md5sum);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] file %s, md5sum %s\n",
                           c_word_to_ipv4(crfsnp_tcid),
                           CMPI_CRFS_RANK,
                           (char *)cstring_get_str(fname),
                           c_md5_to_hex_str(CMD5_DIGEST_SUM(&md5sum))
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] file %s\n",
                           c_word_to_ipv4(crfsnp_tcid),
                           CMPI_CRFS_RANK,
                           (char *)cstring_get_str(fname)
                           );
    }

    return (EC_TRUE);
}

#endif

#if 1

#if 0
EC_BOOL api_cmd_ui_crfsc_create_npp(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_model;
    UINT32   crfscnp_max_num;
    UINT32   crfscnp_2nd_chash_algo_id;
    CSTRING *crfscnp_db_root_dir;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &crfscnp_model);
    api_cmd_para_vec_get_uint32(param  , 1, &crfscnp_max_num);
    api_cmd_para_vec_get_uint32(param  , 2, &crfscnp_2nd_chash_algo_id);
    api_cmd_para_vec_get_cstring(param , 3, &crfscnp_db_root_dir);
    api_cmd_para_vec_get_tcid(param    , 4, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*hsrfsc create np model <model> max num <np mum> with hash algo <id> and root <root dir> on tcid <tcid> at <where>*/
    /*hsrfsc create np model %n max num %n with hash algo %n and root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_create_npp: hsrfsc create np model %u max num %u with hash algo %u and root %s on tcid %s at %s\n",
                        crfscnp_model,
                        crfscnp_max_num,
                        crfscnp_2nd_chash_algo_id,
                        (char *)cstring_get_str(crfscnp_db_root_dir),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_create_npp, CMPI_ERROR_MODI,
             crfscnp_model, crfscnp_max_num, crfscnp_2nd_chash_algo_id, crfscnp_db_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfsc create np model %u max num %u with hash algo %u and root %s on tcid %s successfully\n",
                        crfscnp_model,
                        crfscnp_max_num,
                        crfscnp_2nd_chash_algo_id,
                        (char *)cstring_get_str(crfscnp_db_root_dir),
                        c_word_to_ipv4(crfscnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfsc create np model %u max num %u with hash algo %u and root %s on tcid %s failed\n",
                        crfscnp_model,
                        crfscnp_max_num,
                        crfscnp_2nd_chash_algo_id,
                        (char *)cstring_get_str(crfscnp_db_root_dir),
                        c_word_to_ipv4(crfscnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_create_dn(CMD_PARA_VEC * param)
{
    CSTRING *crfscnp_dn_root_dir;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &crfscnp_dn_root_dir);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc create dn with root <root dir> on tcid <tcid> at <where>*/
    /*hsrfsc create dn with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_create_dn: hsrfsc create dn with root %s on tcid %s at %s\n",
                        (char *)cstring_get_str(crfscnp_dn_root_dir),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_create_dn, CMPI_ERROR_MODI, crfscnp_dn_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfsc create dn with root %s on tcid %s successfully\n",
                        (char *)cstring_get_str(crfscnp_dn_root_dir),
                        c_word_to_ipv4(crfscnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfsc create dn with root %s on tcid %s failed\n",
                        (char *)cstring_get_str(crfscnp_dn_root_dir),
                        c_word_to_ipv4(crfscnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_add_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc add disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfsc add disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_add_disk: hsrfsc add disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_add_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfsc add disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfsc add disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_del_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc del disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfsc del disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_del_disk: hsrfsc del disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_del_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfsc del disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfsc del disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_mount_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc mount disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfsc mount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_mount_disk: hsrfsc mount disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_mount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfsc mount disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfsc mount disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_umount_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc umount disk <disk no> on tcid <tcid> at <where>*/
    /*hsrfsc umount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_umount_disk: hsrfsc umount disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_umount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsrfsc umount disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsrfsc umount disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(crfscnp_tcid));
    }

    return (EC_TRUE);
}

#endif
EC_BOOL api_cmd_ui_crfsc_open(CMD_PARA_VEC * param)
{
    CSTRING *crfsc_root_dir;
    UINT32   crfscnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_cstring(param , 0, &crfsc_root_dir);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);

    /*hsrfsc open from root <dir> on tcid <tcid>*/
    /*hsrfsc open from root %s on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_open: hsrfsc open from root %s on tcid %s\n",
                        (char *)cstring_get_str(crfsc_root_dir),
                        c_word_to_ipv4(crfscnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(crfscnp_tcid, CMPI_CRFSC_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*crfsc_md_id = 0*/

    task_act(mod_mgr_def, NULL_PTR, TASK_DEFAULT_LIVE, (UINT32)1, LOAD_BALANCING_LOOP, TASK_PRIO_NORMAL,
             FI_crfsc_start, crfsc_root_dir);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_close(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_tcid(param    , 0, &crfscnp_tcid);

    /*hsrfsc close on tcid <tcid>*/
    /*hsrfsc close on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_close: hsrfsc close on tcid %s\n",
                        c_word_to_ipv4(crfscnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(crfscnp_tcid, CMPI_CRFSC_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*crfsc_md_id = 0*/

    task_dea(mod_mgr_def, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_crfsc_end, CMPI_ERROR_MODI);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_read(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;

    LOG       *des_log;
    EC_BOOL    ret;


    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc read file <name> on tcid <tcid> at <where>*/
    /*hsrfsc read file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_read: hsrfsc read file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_read, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_crfsc_read: read %s result: %.*s\n",
                          (char *)cstring_get_str(file_name),
                          cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_crfsc_read: read %s failed\n", (char *)cstring_get_str(file_name));
    }

    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_write(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    CSTRING *file_content;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_cstring(param , 1, &file_content);
    api_cmd_para_vec_get_tcid(param    , 2, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfsc write file <name> with content <string> on tcid <tcid> at <where>*/
    /*hsrfsc write file %s with content %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_write: hsrfsc write file %s with content %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        (char *)cstring_get_str(file_content),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    cbytes_mount(cbytes,cstring_get_len(file_content), cstring_get_str(file_content));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_write, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] file name %s\n", (char *)cstring_get_str(file_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] file name %s\n", (char *)cstring_get_str(file_name));
    }

    cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_search_file(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc search file <path> on tcid <tcid> at <where>*/
    /*hsrfsc search file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_search_file: hsrfsc search file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_find_file, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_search_dir(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc search dir <path> on tcid <tcid> at <where>*/
    /*hsrfsc search dir %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_search_dir: hsrfsc search dir %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_find_dir, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_count_file_size(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    uint64_t  file_size;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc count file size of <path> on tcid <tcid> at <where>*/
    /*hsrfsc count file size of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_file_size: hsrfsc count file size of path %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_file_size, CMPI_ERROR_MODI, path_name, &file_size);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file size of path %s: %"PRId64"\n", (char *)cstring_get_str(path_name), file_size);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file size of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_qfile(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    CSTRING *where;
    UINT32   crfscnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CRFSNP_ITEM *crfscnp_item;
    CRFSNP_KEY  *crfscnp_key;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsrfsc qfile %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(crfscnp_tcid, CMPI_ANY_COMM, CMPI_CRFSC_RANK, 0, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfsc_qfile beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_crfsc_qfile end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;
    crfscnp_item = crfsnp_item_new();
    ASSERT(NULL_PTR != crfscnp_item);

    crfscnp_key = crfsnp_key_new();
    ASSERT(NULL_PTR != crfscnp_key);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, crfscnp_tcid, &ret, FI_crfsc_qfile, CMPI_ERROR_MODI, file_name, crfscnp_item, crfscnp_key);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        crfsnp_item_print(des_log, crfscnp_item);
        crfsnp_key_print(des_log, crfscnp_key);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    crfsnp_item_free(crfscnp_item);
    crfsnp_key_free(crfscnp_key);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_delete_file(CMD_PARA_VEC * param)
{
    CSTRING *fname;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &fname);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc delete file <name> on tcid <tcid> at <where>*/
    /*hsrfsc delete file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_delete_file: hsrfsc delete file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_delete_file, CMPI_ERROR_MODI, fname);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete file %s\n", (char *)cstring_get_str(fname));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete file %s\n", (char *)cstring_get_str(fname));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_delete_dir(CMD_PARA_VEC * param)
{
    CSTRING *dname;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &dname);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc delete dir <name> on tcid <tcid> at <where>*/
    /*hsrfsc delete dir %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_delete_dir: hsrfsc delete dir %s on tcid %s at %s\n",
                        (char *)cstring_get_str(dname),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_delete_dir, CMPI_ERROR_MODI, dname);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete dir %s\n", (char *)cstring_get_str(dname));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete dir %s\n", (char *)cstring_get_str(dname));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_delete_path(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc delete path <name> on tcid <tcid> at <where>*/
    /*hsrfsc delete path %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_delete_path: hsrfsc delete path %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_delete, CMPI_ERROR_MODI, path_name, (UINT32)CRFSNP_ITEM_FILE_IS_ANY);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete path %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_recycle(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hsrfsc recycle on tcid <tcid> at <where>*/
    /*hsrfsc recycle on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_recycle: hsrfsc recycle on tcid %s at %s\n",
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_recycle, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] recycle\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] recycle\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_md5sum(CMD_PARA_VEC * param)
{
    CSTRING *fname;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;
    CMD5_DIGEST md5sum;

    api_cmd_para_vec_get_cstring(param , 0, &fname);
    api_cmd_para_vec_get_tcid(param    , 1, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsrfsc md5sum file <name> on tcid <tcid> at <where>*/
    /*hsrfsc md5sum file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_md5sum: hsrfsc md5sum file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_file_md5sum, CMPI_ERROR_MODI, fname, &md5sum);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] file %s, md5sum %s\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(fname),
                           c_md5_to_hex_str(CMD5_DIGEST_SUM(&md5sum))
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] file %s\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(fname)
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_add_dir(CMD_PARA_VEC * param)
{
    CSTRING *dir_name;
    UINT32   dir_tcid;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &dir_name);
    api_cmd_para_vec_get_tcid(param    , 1, &dir_tcid);
    api_cmd_para_vec_get_tcid(param    , 2, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfsc add dir <name> <tcid> on tcid <tcid> at <where>*/
    /*hsrfsc add dir %s %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_add_dir: hsrfsc add dir %s %s on tcid %s at %s\n",
                        (char *)cstring_get_str(dir_name),
                        c_word_to_ipv4(dir_tcid),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_add_dir, CMPI_ERROR_MODI, dir_tcid, dir_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] add dir '%s'\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(dir_name)
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] add dir '%s'\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(dir_name)
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_del_dir(CMD_PARA_VEC * param)
{
    CSTRING *dir_name;
    UINT32   dir_tcid;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &dir_name);
    api_cmd_para_vec_get_tcid(param    , 1, &dir_tcid);
    api_cmd_para_vec_get_tcid(param    , 2, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfsc del dir <name> <tcid> on tcid <tcid> at <where>*/
    /*hsrfsc del dir %s %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_del_dir: hsrfsc del dir %s %s on tcid %s at %s\n",
                        (char *)cstring_get_str(dir_name),
                        c_word_to_ipv4(dir_tcid),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_del_dir, CMPI_ERROR_MODI, dir_tcid, dir_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] del dir '%s'\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(dir_name)
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] del dir '%s'\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(dir_name)
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_has_dir(CMD_PARA_VEC * param)
{
    CSTRING *dir_name;
    UINT32   dir_tcid;
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &dir_name);
    api_cmd_para_vec_get_tcid(param    , 1, &dir_tcid);
    api_cmd_para_vec_get_tcid(param    , 2, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsrfsc has dir <name> <tcid> on tcid <tcid> at <where>*/
    /*hsrfsc has dir %s %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_has_dir: hsrfsc has dir %s %s on tcid %s at %s\n",
                        (char *)cstring_get_str(dir_name),
                        c_word_to_ipv4(dir_tcid),
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_has_dir, CMPI_ERROR_MODI, dir_tcid, dir_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] has dir '%s'\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(dir_name)
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] has dir '%s'\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK,
                           (char *)cstring_get_str(dir_name)
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_clone_dt(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hsrfsc clone dt on tcid <tcid> at <where>*/
    /*hsrfsc clone dt on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_clone_dt: hsrfsc clone dt on tcid %s at %s\n",
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_clone_dt, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] clone dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] clone dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_rollback_dt(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hsrfsc rollback dt on tcid <tcid> at <where>*/
    /*hsrfsc rollback dt on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_rollback_dt: hsrfsc rollback dt on tcid %s at %s\n",
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_rollback_dt, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] rollback dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] rollback dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_flush_dt(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hsrfsc flush dt on tcid <tcid> at <where>*/
    /*hsrfsc flush dt on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_flush_dt: hsrfsc flush dt on tcid %s at %s\n",
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_flush_dt, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] flush dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] flush dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_load_dt(CMD_PARA_VEC * param)
{
    UINT32   crfscnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &crfscnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hsrfsc load dt on tcid <tcid> at <where>*/
    /*hsrfsc load dt on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_load_dt: hsrfsc load dt on tcid %s at %s\n",
                        c_word_to_ipv4(crfscnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfscnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfsc_load_dt, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] load dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] load dt\n",
                           c_word_to_ipv4(crfscnp_tcid),
                           CMPI_CRFSC_RANK
                           );
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_crfsc_show_dt(CMD_PARA_VEC * param)
{
    UINT32   crfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;

    api_cmd_para_vec_get_tcid(param    , 0, &crfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hsrfsc show dt on tcid <tcid> at <where>*/
    /*hsrfsc show dt on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_crfsc_show_dt: hsrfsc show dt on tcid %s at %s\n",
                        c_word_to_ipv4(crfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = crfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CRFSC_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             NULL_PTR,
             FI_crfsc_print_dt, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    sys_log(des_log, "[rank_%s_%ld]\n%s", c_word_to_ipv4(crfsnp_tcid),CMPI_CRFSC_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
    log_cstr_close(log);

    return (EC_TRUE);
}

#endif

#if 1
EC_BOOL api_cmd_ui_cxfs_create_npp(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfsnp_model;
    UINT32   cxfsnp_max_num;
    UINT32   cxfsnp_2nd_chash_algo_id;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &cxfsnp_model);
    api_cmd_para_vec_get_uint32(param  , 2, &cxfsnp_max_num);
    api_cmd_para_vec_get_uint32(param  , 3, &cxfsnp_2nd_chash_algo_id);
    api_cmd_para_vec_get_tcid(param    , 4, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*hsxfs <id> create np model <model> max num <np mum> with hash algo <id> on tcid <tcid> at <where>*/
    /*hsxfs %n create np model %n max num %n with hash algo %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_create_npp: hsxfs %ld create np model %ld max num %ld with hash algo %ld on tcid %s at %s\n",
                        cxfs_modi,
                        cxfsnp_model,
                        cxfsnp_max_num,
                        cxfsnp_2nd_chash_algo_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_create_npp, CMPI_ERROR_MODI,
             cxfsnp_model, cxfsnp_max_num, cxfsnp_2nd_chash_algo_id);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld create np model %u max num %u with hash algo %u on tcid %s successfully\n",
                        cxfs_modi,
                        cxfsnp_model,
                        cxfsnp_max_num,
                        cxfsnp_2nd_chash_algo_id,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld create np model %u max num %u with hash algo %u on tcid %s failed\n",
                        cxfs_modi,
                        cxfsnp_model,
                        cxfsnp_max_num,
                        cxfsnp_2nd_chash_algo_id,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_create_dn(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> create dn on tcid <tcid> at <where>*/
    /*hsxfs %n create dn on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_create_dn: hsxfs %ld create dn on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_create_dn, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld create dn on tcid %s successfully\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld create dn on tcid %s failed\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_create_sata_bad_bitmap(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> create sata bad bitmap on tcid <tcid> at <where>*/
    /*hsxfs %n create sata bad bitmap on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_create_sata_bad_bitmap: hsxfs %ld create sata bad bitmap on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_create_sata_bad_bitmap, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld create sata bad bitmap on tcid %s successfully\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld create sata bad bitmap on tcid %s failed\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_set_sata_bad_page(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   sata_page_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &sata_page_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> set sata bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n set sata bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_set_sata_bad_page: hsxfs %ld set sata bad page %ld on tcid %s at %s\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_set_sata_bad_page, CMPI_ERROR_MODI, sata_page_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld set sata bad page %ld on tcid %s successfully\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld set sata bad page %ld on tcid %s failed\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_unset_sata_bad_page(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   sata_page_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &sata_page_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> unset sata bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n unset sata bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_unset_sata_bad_page: hsxfs %ld unset sata bad page %ld on tcid %s at %s\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_unset_sata_bad_page, CMPI_ERROR_MODI, sata_page_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld unset sata bad page %ld on tcid %s successfully\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld unset sata bad page %ld on tcid %s failed\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_check_sata_bad_page(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   sata_page_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &sata_page_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> check sata bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n check sata bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_check_sata_bad_page: hsxfs %ld check sata bad page %ld on tcid %s at %s\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_check_sata_bad_page, CMPI_ERROR_MODI, sata_page_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld check sata bad page %ld on tcid %s successfully\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld check sata bad page %ld on tcid %s failed\n",
                        cxfs_modi,
                        sata_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_sata_bad_pages(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG       *log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show sata bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n show sata bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_sata_bad_pages: hsxfs %ld show sata bad pages on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    log = log_cstr_open();
    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_sata_bad_pages, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] \n%s",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] \n%s",
                          c_word_to_ipv4(cxfs_tcid),
                          CMPI_CXFS_RANK,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_set_ssd_bad_page(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   ssd_page_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &ssd_page_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> set ssd bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n set ssd bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_set_ssd_bad_page: hsxfs %ld set ssd bad page %ld on tcid %s at %s\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_set_ssd_bad_page, CMPI_ERROR_MODI, ssd_page_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld set ssd bad page %ld on tcid %s successfully\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld set ssd bad page %ld on tcid %s failed\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_unset_ssd_bad_page(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   ssd_page_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &ssd_page_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> unset ssd bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n unset ssd bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_unset_ssd_bad_page: hsxfs %ld unset ssd bad page %ld on tcid %s at %s\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_unset_ssd_bad_page, CMPI_ERROR_MODI, ssd_page_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld unset ssd bad page %ld on tcid %s successfully\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld unset ssd bad page %ld on tcid %s failed\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_check_ssd_bad_page(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   ssd_page_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &ssd_page_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> check ssd bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n check ssd bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_check_ssd_bad_page: hsxfs %ld check ssd bad page %ld on tcid %s at %s\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_check_ssd_bad_page, CMPI_ERROR_MODI, ssd_page_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld check ssd bad page %ld on tcid %s successfully\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld check ssd bad page %ld on tcid %s failed\n",
                        cxfs_modi,
                        ssd_page_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_ssd_bad_pages(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG       *log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show ssd bad page <page no> on tcid <tcid> at <where>*/
    /*hsxfs %n show ssd bad page %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_ssd_bad_pages: hsxfs %ld show ssd bad pages on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    log = log_cstr_open();
    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_ssd_bad_pages, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] \n%s",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] \n%s",
                          c_word_to_ipv4(cxfs_tcid),
                          CMPI_CXFS_RANK,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_add_disk(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   disk_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> add disk <disk no> on tcid <tcid> at <where>*/
    /*hsxfs %n add disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_add_disk: hsxfs %ld add disk %ld on tcid %s at %s\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_add_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld add disk %ld on tcid %s successfully\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld add disk %ld on tcid %s failed\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_del_disk(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   disk_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> del disk <disk no> on tcid <tcid> at <where>*/
    /*hsxfs %n del disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_del_disk: hsxfs %ld del disk %ld on tcid %s at %s\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_del_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld del disk %ld on tcid %s successfully\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld del disk %ld on tcid %s failed\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_mount_disk(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   disk_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> mount disk <disk no> on tcid <tcid> at <where>*/
    /*hsxfs %n mount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_mount_disk: hsxfs %ld mount disk %ld on tcid %s at %s\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_mount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld mount disk %ld on tcid %s successfully\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld mount disk %ld on tcid %s failed\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_umount_disk(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   disk_no;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> umount disk <disk no> on tcid <tcid> at <where>*/
    /*hsxfs %n umount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_umount_disk: hsxfs %ld umount disk %ld on tcid %s at %s\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_umount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hsxfs %ld umount disk %ld on tcid %s successfully\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hsxfs %ld umount disk %ld on tcid %s failed\n",
                        cxfs_modi,
                        disk_no,
                        c_word_to_ipv4(cxfs_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_open(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *sata_disk_path;
    CSTRING *ssd_disk_path;
    UINT32   cxfs_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &sata_disk_path);
    api_cmd_para_vec_get_cstring(param , 2, &ssd_disk_path);
    api_cmd_para_vec_get_tcid(param    , 3, &cxfs_tcid);

    /*hsxfs <id> open from sata <path> and ssd <path|none> on tcid <tcid>*/
    /*hsxfs %n open from sata %s and ssd %s on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_open: hsxfs %ld open from sata %s and ssd %s on tcid %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(sata_disk_path),
                        (char *)cstring_get_str(ssd_disk_path),
                        c_word_to_ipv4(cxfs_tcid));

    if(EC_TRUE == cstring_is_str_ignore_case(ssd_disk_path, (const UINT8 *)"none")
    || EC_TRUE == cstring_is_str_ignore_case(ssd_disk_path, (const UINT8 *)"null"))
    {
        cstring_clean(ssd_disk_path);
    }
    mod_mgr_def = api_cmd_ui_gen_mod_mgr(cxfs_tcid, CMPI_CXFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, cxfs_modi);

    task_act(mod_mgr_def, NULL_PTR, TASK_DEFAULT_LIVE, (UINT32)1, LOAD_BALANCING_LOOP, TASK_PRIO_NORMAL,
             FI_cxfs_start, sata_disk_path, ssd_disk_path);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_close(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);

    /*hsxfs <id> close on tcid <tcid>*/
    /*hsxfs %n close on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_close: hsxfs %ld close on tcid %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(cxfs_tcid, CMPI_CXFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, cxfs_modi);

    task_dea(mod_mgr_def, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_cxfs_end, CMPI_ERROR_MODI);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_read(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *file_name;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &file_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> read file <name> on tcid <tcid> at <where>*/
    /*hsxfs %n read file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_read: hsxfs %ld read file %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_read, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_cxfs_read: read %s result: \n%.*s\n",
                          (char *)cstring_get_str(file_name),
                          cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_cxfs_read: read %s failed\n", (char *)cstring_get_str(file_name));
    }

    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_write(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *file_name;
    CSTRING *file_content;
//    UINT32   expire_nsec;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &file_name);
    api_cmd_para_vec_get_cstring(param , 2, &file_content);
    //api_cmd_para_vec_get_uint32(param  , 3, &expire_nsec);
    api_cmd_para_vec_get_tcid(param    , 3, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*hsxfs <id> write file <name> with content <string> on tcid <tcid> at <where>*/
    /*hsxfs %n write file %s with content %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_write: hsxfs %ld write file %s with content %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(file_name),
                        (char *)cstring_get_str(file_content),
                        /*expire_nsec,*/
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    cbytes_mount(cbytes,cstring_get_len(file_content), cstring_get_str(file_content));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_write, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] file name %s\n", (char *)cstring_get_str(file_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] file name %s\n", (char *)cstring_get_str(file_name));
    }

    cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_mkdir(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path_name;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> mkdir <path> on tcid <tcid> at <where>*/
    /*hsxfs %n mkdir %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_mkdir: hsxfs %ld mkdir %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_mkdir, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] mkdir %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] mkdir %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_search(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path_name;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> search <path> on tcid <tcid> at <where>*/
    /*hsxfs %n search %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_search: hsxfs %ld search %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_search, CMPI_ERROR_MODI, path_name, (UINT32)CXFSNP_ITEM_FILE_IS_ANY);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_count_file_num(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path_name;
    UINT32   cxfs_tcid;
    CSTRING *where;

    UINT32   file_num;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> count file num of <path> on tcid <tcid> at <where>*/
    /*hsxfs %n count file num of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_count_file_num: hsxfs %ld count file num of path %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_file_num, CMPI_ERROR_MODI, path_name, &file_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file num of path %s: %ld\n", (char *)cstring_get_str(path_name), file_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file num of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_count_file_size(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path_name;
    UINT32   cxfs_tcid;
    CSTRING *where;

    uint64_t  file_size;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> count file size of <path> on tcid <tcid> at <where>*/
    /*hsxfs %n count file size of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_file_size: hsxfs %ld count file size of path %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_file_size, CMPI_ERROR_MODI, path_name, &file_size);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file size of path %s: %"PRId64"\n", (char *)cstring_get_str(path_name), file_size);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file size of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qfile(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *file_name;
    CSTRING *where;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CXFSNP_ITEM *cxfsnp_item;
    CXFSNP_KEY  *cxfsnp_key;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &file_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qfile %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qfile beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qfile end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;
    cxfsnp_item = cxfsnp_item_new();
    ASSERT(NULL_PTR != cxfsnp_item);

    cxfsnp_key = cxfsnp_key_new();
    ASSERT(NULL_PTR != cxfsnp_key);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qfile, CMPI_ERROR_MODI, file_name, cxfsnp_item, cxfsnp_key);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        cxfsnp_item_print(des_log, cxfsnp_item);
        cxfsnp_key_print(des_log, cxfsnp_key);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    cxfsnp_item_free(cxfsnp_item);
    cxfsnp_key_free(cxfsnp_key);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qdir(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *dir_name;
    CSTRING *where;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CXFSNP_ITEM *cxfsnp_item;
    CXFSNP_KEY  *cxfsnp_key;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &dir_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qdir %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(dir_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qdir beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qdir end ----------------------------------\n");
    }
#endif

    cxfsnp_item = cxfsnp_item_new();
    ASSERT(NULL_PTR != cxfsnp_item);

    cxfsnp_key = cxfsnp_key_new();
    ASSERT(NULL_PTR != cxfsnp_key);

    ret = EC_FALSE;

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qdir, CMPI_ERROR_MODI, dir_name, cxfsnp_item, cxfsnp_key);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC]\n");
        cxfsnp_item_print(des_log, cxfsnp_item);
        cxfsnp_key_print(des_log, cxfsnp_key);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    cxfsnp_item_free(cxfsnp_item);
    cxfsnp_key_free(cxfsnp_key);
    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qlist_path_of_np(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   cxfsnp_id;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *path_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_uint32(param  , 2, &cxfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 3, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qlist %s full of np %ld on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path),
                        cxfsnp_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_path_of_np beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_path_of_np end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0424);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qlist_path_of_np, CMPI_ERROR_MODI, path, cxfsnp_id, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }

    cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0425);
    cvector_free(path_cstr_vec, LOC_API_0426);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qlist_seg_of_np(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   cxfsnp_id;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *seg_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_uint32(param  , 2, &cxfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 3, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qlist %s short of np %ld on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path),
                        cxfsnp_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_seg_of_np beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_seg_of_np end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    seg_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0427);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qlist_seg_of_np, CMPI_ERROR_MODI, path, cxfsnp_id, seg_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }

    cvector_clean(seg_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0428);
    cvector_free(seg_cstr_vec, LOC_API_0429);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qlist_path(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *path_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qlist %s full on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_path beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_path end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0430);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qlist_path, CMPI_ERROR_MODI, path, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }

    cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0431);
    cvector_free(path_cstr_vec, LOC_API_0432);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qlist_seg(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *seg_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qlist %s short on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_seg beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_seg end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    seg_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0433);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qlist_seg, CMPI_ERROR_MODI, path, seg_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(seg_cstr_vec); pos ++)
        {
            CSTRING *seg_cstr;

            seg_cstr = (CSTRING *)cvector_get(seg_cstr_vec, pos);
            if(NULL_PTR == seg_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(seg_cstr));
        }
    }

    cvector_clean(seg_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0434);
    cvector_free(seg_cstr_vec, LOC_API_0435);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qlist_tree_of_np(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   cxfsnp_id;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *tree_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_uint32(param  , 2, &cxfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 3, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qlist %s tree of np %ld on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path),
                        cxfsnp_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_tree_of_np beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_tree_of_np end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    tree_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0436);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qlist_tree_of_np, CMPI_ERROR_MODI, cxfsnp_id, path, tree_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(tree_cstr_vec); pos ++)
        {
            CSTRING *tree_cstr;

            tree_cstr = (CSTRING *)cvector_get(tree_cstr_vec, pos);
            if(NULL_PTR == tree_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(tree_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(tree_cstr_vec); pos ++)
        {
            CSTRING *tree_cstr;

            tree_cstr = (CSTRING *)cvector_get(tree_cstr_vec, pos);
            if(NULL_PTR == tree_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(tree_cstr));
        }
    }

    cvector_clean(tree_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0437);
    cvector_free(tree_cstr_vec, LOC_API_0438);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_qlist_tree(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path;
    CSTRING *where;
    UINT32   cxfs_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CVECTOR     *path_cstr_vec;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hsxfs %ld qlist %s tree on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(cxfs_tcid, CMPI_ANY_COMM, CMPI_CXFS_RANK, cxfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_tree beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_cxfs_qlist_tree end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;

    path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_API_0439);

    task_mgr = task_new(mod_mgr, TASK_PRIO_HIGH, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, cxfs_tcid, &ret, FI_cxfs_qlist_tree, CMPI_ERROR_MODI, path, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        UINT32 pos;

        sys_log(des_log, "[SUCC]\n");
        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }
    else
    {
        UINT32 pos;
        sys_log(des_log, "[FAIL]\n");

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            CSTRING *path_cstr;

            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);
            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            sys_log(des_log, "%ld # %s\n", pos, (char *)cstring_get_str(path_cstr));
        }
    }

    cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_API_0440);
    cvector_free(path_cstr_vec, LOC_API_0441);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_delete_file(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *fname;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &fname);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> delete file <name> on tcid <tcid> at <where>*/
    /*hsxfs %n delete file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_delete_file: hsxfs %ld delete file %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_delete_file, CMPI_ERROR_MODI, fname);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete file %s\n", (char *)cstring_get_str(fname));
        sys_log(LOGCONSOLE, "[SUCC] delete file %s\n", (char *)cstring_get_str(fname));
        if(des_log == LOGCONSOLE)
        {
            sys_log(LOGCONSOLE, "[SUCC] des_log is CONSOLE\n");
        }
        else
        {
            sys_log(LOGCONSOLE, "[SUCC] des_log is NOT CONSOLE\n");
        }
    }
    else
    {
        sys_log(des_log, "[FAIL] delete file %s\n", (char *)cstring_get_str(fname));
        sys_log(LOGCONSOLE, "[FAIL] delete file %s\n", (char *)cstring_get_str(fname));
        if(des_log == LOGCONSOLE)
        {
            sys_log(LOGCONSOLE, "[FAIL] des_log is CONSOLE\n");
        }
        else
        {
            sys_log(LOGCONSOLE, "[FAIL] des_log is NOT CONSOLE\n");
        }
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_delete_dir(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *dname;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    EC_BOOL   is_root_dir;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &dname);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> delete dir <name> on tcid <tcid> at <where>*/
    /*hsxfs %n delete dir %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_delete_dir: hsxfs %ld delete dir %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(dname),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;


    des_log = api_cmd_ui_get_log(where);

    ret = EC_FALSE;

    /* ensure the dir to delete is NOT root dir / */
    is_root_dir = cstring_is_str((const CSTRING *)dname, (const UINT8 *)"/");
    if(EC_FALSE == is_root_dir)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_delete_dir, CMPI_ERROR_MODI, dname);
    }
    else
    {
        sys_log(des_log, "[ERRO] can NOT use this interface to delete root dir %s \n", (char *)cstring_get_str(dname));
        //sys_log(des_log, "[WARN] to delete root dir, use command: hsxfs <id> delete root dir / on tcid <tcid> at <console|log>\n");
    }

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete dir %s\n", (char *)cstring_get_str(dname));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete dir %s\n", (char *)cstring_get_str(dname));
    }

    return (EC_TRUE);
}


EC_BOOL api_cmd_ui_cxfs_delete_root_dir(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *dname;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    EC_BOOL   is_root_dir;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &dname);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_delete_root_dir: hsxfs %ld delete root dir %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(dname),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;


    des_log = api_cmd_ui_get_log(where);

    ret = EC_FALSE;

    /* ensure the dir to delete is root dir / */
    is_root_dir = cstring_is_str((const CSTRING *)dname, (const UINT8 *)"/");
    if(EC_TRUE == is_root_dir)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_delete_dir, CMPI_ERROR_MODI, dname);
    }
    else
    {
        sys_log(des_log, "[ERRO] the dir %s to delete is not root dir / \n", (char *)cstring_get_str(dname));
    }

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete root dir %s\n", (char *)cstring_get_str(dname));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete dir %s\n", (char *)cstring_get_str(dname));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_delete_path(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *path_name;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &path_name);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs delete path <name> on tcid <tcid> at <where>*/
    /*hsxfs delete path %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_delete_path: hsxfs %ld delete path %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_delete, CMPI_ERROR_MODI, path_name, (UINT32)CXFSNP_ITEM_FILE_IS_ANY);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete path %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_recycle(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;
    UINT32     complete_num;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> recycle on tcid <tcid> at <where>*/
    /*hsxfs %n recycle on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_recycle: hsxfs %ld recycle on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_recycle, CMPI_ERROR_MODI, CXFS_RECYCLE_MAX_NUM, &complete_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] recycle completion num %ld\n", complete_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] recycle\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_retire(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   max_retire_num;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;
    UINT32     complete_retire_num;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &max_retire_num);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> retire max <num> files on tcid <tcid> at <where>*/
    /*hsxfs %n retire max %n files on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_retire: hsxfs %ld retire max %ld files on tcid %s at %s\n",
                        cxfs_modi,
                        max_retire_num,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    complete_retire_num = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_retire, CMPI_ERROR_MODI, max_retire_num, &complete_retire_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] retire %ld files\n", complete_retire_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] retire %ld files\n", complete_retire_num);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_flush(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> flush on tcid <tcid> at <where>*/
    /*hsxfs %n flush on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_flush: hsxfs %ld flush on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_flush, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] flush\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] flush\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_flush_npp(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> flush npp on tcid <tcid> at <where>*/
    /*hsxfs %n flush on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_flush_npp: hsxfs %ld flush npp on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_flush_npp, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] flush npp\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] flush npp\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_flush_dn(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> flush dn on tcid <tcid> at <where>*/
    /*hsxfs %n flush on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_flush_dn: hsxfs %ld flush dn on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_flush_dn, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] flush dn\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] flush dn\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_set_read_only(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> set read only on tcid <tcid> at <where>*/
    /*hsxfs %n set read only on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_set_read_only: hsxfs %ld set read only on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_set_read_only, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] set read only\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] set read only\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_unset_read_only(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> unset read only on tcid <tcid> at <where>*/
    /*hsxfs %n unset read only on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_unset_read_only: hsxfs %ld unset read only on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_unset_read_only, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] unset read only\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] unset read only\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_check_read_only(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> check read only on tcid <tcid> at <where>*/
    /*hsxfs %n check read only on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_check_read_only: hsxfs %ld check read only on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_is_read_only, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] read-only mode\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] not read-only mode\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_sync(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> sync on tcid <tcid> at <where>*/
    /*hsxfs %n sync on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_sync: hsxfs %ld sync on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_sync, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] sync succ\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] sync failed\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_replay_op(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> replay op on tcid <tcid> at <where>*/
    /*hsxfs %n replay op on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_replay_op: hsxfs %ld replay op on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_replay_op, CMPI_ERROR_MODI);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] replay op succ\n");
    }
    else
    {
        sys_log(des_log, "[FAIL] replay op failed\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_pop_op(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   op_size;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &op_size);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> pop op <size> on tcid <tcid> at <where>*/
    /*hsxfs %n pop op %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_pop_op: hsxfs %ld pop op %ld on tcid %s at %s\n",
                        cxfs_modi,
                        op_size,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_pop_op, CMPI_ERROR_MODI, op_size);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] pop op %ld succ\n", op_size);
    }
    else
    {
        sys_log(des_log, "[FAIL] pop op %ld failed\n", op_size);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_npp_lru_list(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show npp lru on tcid <tcid> at <where>*/
    /*hsxfs %n show npp lru on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_npp_lru_list: hsxfs %ld show npp lru on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_npp_lru_list, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_npp_del_list(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show npp del on tcid <tcid> at <where>*/
    /*hsxfs %n show npp del on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_npp_del_list: hsxfs %ld show npp del on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_npp_del_list, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_npp(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show npp on tcid <tcid> at <where>*/
    /*hsxfs %n show npp on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_npp: hsxfs %ld show npp on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_npp, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_dn(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show dn on tcid <tcid> at <where>*/
    /*hsxfs %n show dn on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_dn: hsxfs %ld show dn on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_dn, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(cxfs_tcid),CMPI_CXFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_specific_np_lru_list(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfsnp_id;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &cxfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> show specific np <id> lru on tcid <tcid> at <where>*/
    /*hsxfs %n show specific np %n lru on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_specific_np_lru_list: hsxfs %ld show specific np %ld lru on tcid %s at %s\n",
                        cxfs_modi,
                        cxfsnp_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_specific_np_lru_list, CMPI_ERROR_MODI, cxfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           cxfsnp_id,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(cxfs_tcid),
                          CMPI_CXFS_RANK, cxfsnp_id,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_specific_np_del_list(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfsnp_id;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &cxfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> show specific np <id> del on tcid <tcid> at <where>*/
    /*hsxfs %n show specific np %n del on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_specific_np_del_list: hsxfs %ld show specific np %ld del on tcid %s at %s\n",
                        cxfs_modi,
                        cxfsnp_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_specific_np_del_list, CMPI_ERROR_MODI, cxfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           cxfsnp_id,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(cxfs_tcid),
                          CMPI_CXFS_RANK, cxfsnp_id,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_specific_np(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfsnp_id;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_uint32(param  , 1, &cxfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> show specific np <id> on tcid <tcid> at <where>*/
    /*hsxfs %n show specific np %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_specific_np: hsxfs %ld show specific np %ld on tcid %s at %s\n",
                        cxfs_modi,
                        cxfsnp_id,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_show_specific_np, CMPI_ERROR_MODI, cxfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           cxfsnp_id,
                           (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(cxfs_tcid),
                          CMPI_CXFS_RANK, cxfsnp_id,
                          (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_show_locked_files(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_tcid(param    , 1, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hsxfs <id> show locked files on tcid <tcid> at <console|log>*/
    /*hsxfs %n show locked files on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_show_locked_files: hsxfs %ld locked files on tcid %s at %s\n",
                        cxfs_modi,
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             NULL_PTR,
             FI_cxfs_locked_files_print, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    sys_log(des_log, "[rank_%s_%ld][SUCC] \n%s",
                       c_word_to_ipv4(cxfs_tcid),
                       CMPI_CXFS_RANK,
                       (char *)cstring_get_str(LOG_CSTR(log)));
    log_cstr_close(log);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cxfs_md5sum(CMD_PARA_VEC * param)
{
    UINT32   cxfs_modi;
    CSTRING *fname;
    UINT32   cxfs_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;
    CMD5_DIGEST md5sum;

    api_cmd_para_vec_get_uint32(param  , 0, &cxfs_modi);
    api_cmd_para_vec_get_cstring(param , 1, &fname);
    api_cmd_para_vec_get_tcid(param    , 2, &cxfs_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hsxfs <id> md5sum file <name> on tcid <tcid> at <where>*/
    /*hsxfs %n md5sum file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cxfs_md5sum: hsxfs %ld md5sum file %s on tcid %s at %s\n",
                        cxfs_modi,
                        (char *)cstring_get_str(fname),
                        c_word_to_ipv4(cxfs_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = cxfs_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CXFS_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cxfs_file_md5sum, CMPI_ERROR_MODI, fname, &md5sum);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] file %s, md5sum %s\n",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           (char *)cstring_get_str(fname),
                           c_md5_to_hex_str(CMD5_DIGEST_SUM(&md5sum))
                           );
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] file %s\n",
                           c_word_to_ipv4(cxfs_tcid),
                           CMPI_CXFS_RANK,
                           (char *)cstring_get_str(fname)
                           );
    }

    return (EC_TRUE);
}

#endif


#if 1
EC_BOOL api_cmd_ui_chfs_create_npp(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_model;
    UINT32   chfsnp_max_num;
    CSTRING *chfsnp_db_root_dir;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &chfsnp_model);
    api_cmd_para_vec_get_uint32(param  , 1, &chfsnp_max_num);
    api_cmd_para_vec_get_cstring(param , 2, &chfsnp_db_root_dir);
    api_cmd_para_vec_get_tcid(param    , 3, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*hshfs create np model <model> max num <np mum> with root <root dir> on tcid <tcid> at <where>*/
    /*hshfs create np model %n max num %n with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_create_npp: hshfs create np model %ld max num %ld with root %s on tcid %s at %s\n",
                        chfsnp_model,
                        chfsnp_max_num,
                        (char *)cstring_get_str(chfsnp_db_root_dir),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_create_npp, CMPI_ERROR_MODI,
             chfsnp_model, chfsnp_max_num, chfsnp_db_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hshfs create np model %ld max num %ld with root %s on tcid %s successfully\n",
                        chfsnp_model,
                        chfsnp_max_num,
                        (char *)cstring_get_str(chfsnp_db_root_dir),
                        c_word_to_ipv4(chfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hshfs create np model %ld max num %ld with root %s on tcid %s failed\n",
                        chfsnp_model,
                        chfsnp_max_num,
                        (char *)cstring_get_str(chfsnp_db_root_dir),
                        c_word_to_ipv4(chfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_create_dn(CMD_PARA_VEC * param)
{
    CSTRING *chfsnp_dn_root_dir;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &chfsnp_dn_root_dir);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs create dn with root <root dir> on tcid <tcid> at <where>*/
    /*hshfs create dn with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_create_dn: hshfs create dn with root %s on tcid %s at %s\n",
                        (char *)cstring_get_str(chfsnp_dn_root_dir),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_create_dn, CMPI_ERROR_MODI, chfsnp_dn_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hshfs create dn with root %s on tcid %s successfully\n",
                        (char *)cstring_get_str(chfsnp_dn_root_dir),
                        c_word_to_ipv4(chfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hshfs create dn with root %s on tcid %s failed\n",
                        (char *)cstring_get_str(chfsnp_dn_root_dir),
                        c_word_to_ipv4(chfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_add_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs add disk <disk no> on tcid <tcid> at <where>*/
    /*hshfs add disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_add_disk: hshfs add disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_add_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hshfs add disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hshfs add disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_del_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs del disk <disk no> on tcid <tcid> at <where>*/
    /*hshfs del disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_del_disk: hshfs del disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_del_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hshfs del disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hshfs del disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_mount_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs mount disk <disk no> on tcid <tcid> at <where>*/
    /*hshfs mount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_mount_disk: hshfs mount disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_mount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hshfs mount disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hshfs mount disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_umount_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs umount disk <disk no> on tcid <tcid> at <where>*/
    /*hshfs umount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_umount_disk: hshfs umount disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_umount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hshfs umount disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hshfs umount disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(chfsnp_tcid));
    }

    return (EC_TRUE);
}
EC_BOOL api_cmd_ui_chfs_open(CMD_PARA_VEC * param)
{
    CSTRING *chfsnp_root_dir;
    CSTRING *chfsdn_root_dir;
    UINT32   chfsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_cstring(param , 0, &chfsnp_root_dir);
    api_cmd_para_vec_get_cstring(param , 1, &chfsdn_root_dir);
    api_cmd_para_vec_get_tcid(param    , 2, &chfsnp_tcid);

    /*hshfs open from np root <dir> and dn root <dir> on tcid <tcid>*/
    /*hshfs open from np root %s and dn root %s on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_open: hshfs open from np root %s and dn root %s on tcid %s\n",
                        (char *)cstring_get_str(chfsnp_root_dir),
                        (char *)cstring_get_str(chfsdn_root_dir),
                        c_word_to_ipv4(chfsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(chfsnp_tcid, CMPI_CHFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*chfs_md_id = 0*/

    task_act(mod_mgr_def, NULL_PTR, TASK_DEFAULT_LIVE, (UINT32)1, LOAD_BALANCING_LOOP, TASK_PRIO_NORMAL,
             FI_chfs_start, chfsnp_root_dir, chfsdn_root_dir);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_close(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_tcid(param    , 0, &chfsnp_tcid);

    /*hshfs close on tcid <tcid>*/
    /*hshfs close on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_close: hshfs close on tcid %s\n",
                        c_word_to_ipv4(chfsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(chfsnp_tcid, CMPI_CHFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*chfs_md_id = 0*/

    task_dea(mod_mgr_def, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_chfs_end, CMPI_ERROR_MODI);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_read(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs read file <file name> on tcid <tcid> at <where>*/
    /*hshfs read file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_read: hshfs read file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_read, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_chfs_read: read %s result: \n%.*s\n",
                          (char *)cstring_get_str(file_name),
                          cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_chfs_read: read %s failed\n", (char *)cstring_get_str(file_name));
    }

    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_write(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    CSTRING *file_content;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_cstring(param , 1, &file_content);
    api_cmd_para_vec_get_tcid(param    , 2, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hshfs write file <file name> with content <string> on tcid <tcid> at <where>*/
    /*hshfs write file %s with content %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_write: hshfs write file %s with content %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        (char *)cstring_get_str(file_content),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    cbytes_mount(cbytes,cstring_get_len(file_content), cstring_get_str(file_content));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_write, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] file name %s\n", (char *)cstring_get_str(file_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] file name %s\n", (char *)cstring_get_str(file_name));
    }

    cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_search(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs search <file name> on tcid <tcid> at <where>*/
    /*hshfs search %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_search: hshfs search %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_search, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_qfile(CMD_PARA_VEC * param)
{
    UINT32   chfs_modi;
    CSTRING *file_name;
    CSTRING *where;
    UINT32   chfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CHFSNP_ITEM *chfsnp_item;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hshfs qfile %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    chfs_modi = 0; /*xx*/

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(chfsnp_tcid, CMPI_ANY_COMM, CMPI_CHFS_RANK, chfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_chfs_qfile beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_chfs_qfile end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;
    chfsnp_item = chfsnp_item_new();
    ASSERT(NULL_PTR != chfsnp_item);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, chfsnp_tcid, &ret, FI_chfs_qfile, CMPI_ERROR_MODI, file_name, chfsnp_item);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        chfsnp_item_print(des_log, chfsnp_item);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    chfsnp_item_free(chfsnp_item);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_count_file_num(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_tcid;
    CSTRING *where;

    UINT32   file_num;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hshfs count file num on tcid <tcid> at <where>*/
    /*hshfs count file num on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_count_file_num: hshfs count file num on tcid %s at %s\n",
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_file_num, CMPI_ERROR_MODI, &file_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file num: %ld\n", file_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file num\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_count_file_size(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    uint64_t  file_size;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs count file size of <path> on tcid <tcid> at <where>*/
    /*hshfs count file size of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_file_size: hshfs count file size of path %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_file_size, CMPI_ERROR_MODI, path_name, &file_size);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file size of path %s: %"PRId64"\n", (char *)cstring_get_str(path_name), file_size);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file size of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_delete(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs delete file <file name> on tcid <tcid> at <where>*/
    /*hshfs delete file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_delete: hshfs delete file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_delete, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_recycle(CMD_PARA_VEC * param)
{
    UINT32   chfs_modi;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;
    UINT32     complete_num;

    api_cmd_para_vec_get_tcid(param    , 0, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hshfs recycle on tcid <tcid> at <where>*/
    /*hshfs recycle on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_recycle: hshfs recycle on tcid %s at %s\n",
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    chfs_modi = 0; /*xx*/

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = chfs_modi;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_recycle, CMPI_ERROR_MODI, CHFS_RECYCLE_MAX_NUM, &complete_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] recycle completion num %ld\n", complete_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] recycle\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_retire(CMD_PARA_VEC * param)
{
    UINT32   chfs_modi;
    UINT32   max_retire_num;
    UINT32   nsec;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;
    UINT32     complete_retire_num;

    api_cmd_para_vec_get_uint32(param  , 0, &max_retire_num);
    api_cmd_para_vec_get_uint32(param  , 1, &nsec);
    api_cmd_para_vec_get_tcid(param    , 2, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hshfs retire max <num> files created before <n> seconds on tcid <tcid> at <where>*/
    /*hshfs retire max %n files created before %n seconds on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_retire: hshfs retire max %ld files created before %ld seconds on tcid %s at %s\n",
                        max_retire_num,
                        nsec,
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    chfs_modi = 0; /*xx*/

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = chfs_modi;

    ret = EC_FALSE;
    complete_retire_num = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_retire, CMPI_ERROR_MODI, nsec, max_retire_num, CHFS_RETIRE_MAX_NUM, &complete_retire_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] retire %ld files\n", complete_retire_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] retire %ld files\n", complete_retire_num);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_show_npp(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hshfs show npp on tcid <tcid> at <where>*/
    /*hshfs show npp on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_show_npp: hshfs show npp on tcid %s at %s\n",
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_show_npp, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(chfsnp_tcid),CMPI_CHFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(chfsnp_tcid),CMPI_CHFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_show_dn(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hshfs show dn on tcid <tcid> at <where>*/
    /*hshfs show dn on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_show_dn: hshfs show dn on tcid %s at %s\n",
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_show_dn, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(chfsnp_tcid),CMPI_CHFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(chfsnp_tcid),CMPI_CHFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_show_cached_np(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hshfs show cached np on tcid <tcid> at <where>*/
    /*hshfs show cached np on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_show_cached_np: hshfs show cached np on tcid %s at %s\n",
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_show_cached_np, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(chfsnp_tcid),CMPI_CHFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(chfsnp_tcid),CMPI_CHFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_chfs_show_specific_np(CMD_PARA_VEC * param)
{
    UINT32   chfsnp_id;
    UINT32   chfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &chfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 1, &chfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hshfs show specific np <id> on tcid <tcid> at <where>*/
    /*hshfs show specific np %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_chfs_show_specific_np: hshfs show specific np %ld on tcid %s at %s\n",
                        chfsnp_id,
                        c_word_to_ipv4(chfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = chfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CHFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_chfs_show_specific_np, CMPI_ERROR_MODI, chfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(chfsnp_tcid),
                           CMPI_CHFS_RANK,
                           (char *)cstring_get_str(LOG_CSTR(log)),
                           chfsnp_id);
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(chfsnp_tcid),
                          CMPI_CHFS_RANK,
                          (char *)cstring_get_str(LOG_CSTR(log)),
                          chfsnp_id);
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

#endif

#if 1
EC_BOOL api_cmd_ui_csfs_create_npp(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_model;
    UINT32   csfsnp_max_num;
    CSTRING *csfsnp_db_root_dir;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &csfsnp_model);
    api_cmd_para_vec_get_uint32(param  , 1, &csfsnp_max_num);
    api_cmd_para_vec_get_cstring(param , 2, &csfsnp_db_root_dir);
    api_cmd_para_vec_get_tcid(param    , 3, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*hssfs create np model <model> max num <np mum> with root <root dir> on tcid <tcid> at <where>*/
    /*hssfs create np model %n max num %n with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_create_npp: hssfs create np model %ld max num %ld with root %s on tcid %s at %s\n",
                        csfsnp_model,
                        csfsnp_max_num,
                        (char *)cstring_get_str(csfsnp_db_root_dir),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_create_npp, CMPI_ERROR_MODI,
             csfsnp_model, csfsnp_max_num, csfsnp_db_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hssfs create np model %ld max num %ld with root %s on tcid %s successfully\n",
                        csfsnp_model,
                        csfsnp_max_num,
                        (char *)cstring_get_str(csfsnp_db_root_dir),
                        c_word_to_ipv4(csfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hssfs create np model %ld max num %ld with root %s on tcid %s failed\n",
                        csfsnp_model,
                        csfsnp_max_num,
                        (char *)cstring_get_str(csfsnp_db_root_dir),
                        c_word_to_ipv4(csfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_create_dn(CMD_PARA_VEC * param)
{
    CSTRING *csfsnp_dn_root_dir;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &csfsnp_dn_root_dir);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs create dn with root <root dir> on tcid <tcid> at <where>*/
    /*hssfs create dn with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_create_dn: hssfs create dn with root %s on tcid %s at %s\n",
                        (char *)cstring_get_str(csfsnp_dn_root_dir),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_create_dn, CMPI_ERROR_MODI, csfsnp_dn_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hssfs create dn with root %s on tcid %s successfully\n",
                        (char *)cstring_get_str(csfsnp_dn_root_dir),
                        c_word_to_ipv4(csfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hssfs create dn with root %s on tcid %s failed\n",
                        (char *)cstring_get_str(csfsnp_dn_root_dir),
                        c_word_to_ipv4(csfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_add_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs add disk <disk no> on tcid <tcid> at <where>*/
    /*hssfs add disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_add_disk: hssfs add disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_add_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hssfs add disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hssfs add disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_del_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs del disk <disk no> on tcid <tcid> at <where>*/
    /*hssfs del disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_del_disk: hssfs del disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_del_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hssfs del disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hssfs del disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_mount_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs mount disk <disk no> on tcid <tcid> at <where>*/
    /*hssfs mount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_mount_disk: hssfs mount disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_mount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hssfs mount disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hssfs mount disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_umount_disk(CMD_PARA_VEC * param)
{
    UINT32   disk_no;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &disk_no);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs umount disk <disk no> on tcid <tcid> at <where>*/
    /*hssfs umount disk %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_umount_disk: hssfs umount disk %ld on tcid %s at %s\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_umount_disk, CMPI_ERROR_MODI, disk_no);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] hssfs umount disk %ld on tcid %s successfully\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] hssfs umount disk %ld on tcid %s failed\n",
                        disk_no,
                        c_word_to_ipv4(csfsnp_tcid));
    }

    return (EC_TRUE);
}
EC_BOOL api_cmd_ui_csfs_open(CMD_PARA_VEC * param)
{
    CSTRING *csfsnp_root_dir;
    CSTRING *csfsdn_root_dir;
    UINT32   csfsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_cstring(param , 0, &csfsnp_root_dir);
    api_cmd_para_vec_get_cstring(param , 1, &csfsdn_root_dir);
    api_cmd_para_vec_get_tcid(param    , 2, &csfsnp_tcid);

    /*hssfs open from np root <dir> and dn root <dir> on tcid <tcid>*/
    /*hssfs open from np root %s and dn root %s on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_open: hssfs open from np root %s and dn root %s on tcid %s\n",
                        (char *)cstring_get_str(csfsnp_root_dir),
                        (char *)cstring_get_str(csfsdn_root_dir),
                        c_word_to_ipv4(csfsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(csfsnp_tcid, CMPI_CSFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*csfs_md_id = 0*/

    task_act(mod_mgr_def, NULL_PTR, TASK_DEFAULT_LIVE, (UINT32)1, LOAD_BALANCING_LOOP, TASK_PRIO_NORMAL,
             FI_csfs_start, csfsnp_root_dir, csfsdn_root_dir);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_close(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_tcid(param    , 0, &csfsnp_tcid);

    /*hssfs close on tcid <tcid>*/
    /*hssfs close on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_close: hssfs close on tcid %s\n",
                        c_word_to_ipv4(csfsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(csfsnp_tcid, CMPI_CSFS_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*csfs_md_id = 0*/

    task_dea(mod_mgr_def, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_csfs_end, CMPI_ERROR_MODI);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_read(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs read file <file name> on tcid <tcid> at <where>*/
    /*hssfs read file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_read: hssfs read file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_read, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_csfs_read: read %s result: \n%.*s\n",
                          (char *)cstring_get_str(file_name),
                          cbytes_len(cbytes), (char *)cbytes_buf(cbytes));
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_csfs_read: read %s failed\n", (char *)cstring_get_str(file_name));
    }

    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_write(CMD_PARA_VEC * param)
{
    CSTRING *file_name;
    CSTRING *file_content;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CBYTES    *cbytes;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_cstring(param , 1, &file_content);
    api_cmd_para_vec_get_tcid(param    , 2, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*hssfs write file <file name> with content <string> on tcid <tcid> at <where>*/
    /*hssfs write file %s with content %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_write: hssfs write file %s with content %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        (char *)cstring_get_str(file_content),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;
    cbytes = cbytes_new(0);

    cbytes_mount(cbytes,cstring_get_len(file_content), cstring_get_str(file_content));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_write, CMPI_ERROR_MODI, file_name, cbytes);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] file name %s\n", (char *)cstring_get_str(file_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] file name %s\n", (char *)cstring_get_str(file_name));
    }

    cbytes_umount(cbytes, NULL_PTR, NULL_PTR);
    cbytes_free(cbytes);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_search(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs search <file name> on tcid <tcid> at <where>*/
    /*hssfs search %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_search: hssfs search %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_search, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_qfile(CMD_PARA_VEC * param)
{
    UINT32   csfs_modi;
    CSTRING *file_name;
    CSTRING *where;
    UINT32   csfsnp_tcid;

    MOD_MGR     *mod_mgr;
    TASK_MGR    *task_mgr;
    CSFSNP_ITEM *csfsnp_item;
    LOG         *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &file_name);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "hssfs qfile %s on tcid %s at %s\n",
                        (char *)cstring_get_str(file_name),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    csfs_modi = 0; /*xx*/

    mod_mgr = mod_mgr_new(CMPI_ERROR_MODI, LOAD_BALANCING_LOOP);
    mod_mgr_incl(csfsnp_tcid, CMPI_ANY_COMM, CMPI_CSFS_RANK, csfs_modi, mod_mgr);
#if 1
    if(do_log(SEC_0010_API, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csfs_qfile beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ api_cmd_ui_csfs_qfile end ----------------------------------\n");
    }
#endif

    ret = EC_FALSE;
    csfsnp_item = csfsnp_item_new();
    ASSERT(NULL_PTR != csfsnp_item);

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_tcid_inc(task_mgr, csfsnp_tcid, &ret, FI_csfs_qfile, CMPI_ERROR_MODI, file_name, csfsnp_item);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        csfsnp_item_print(des_log, csfsnp_item);
    }
    else
    {
        sys_log(des_log, "[FAIL]\n");
    }

    csfsnp_item_free(csfsnp_item);

    mod_mgr_free(mod_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_count_file_num(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_tcid;
    CSTRING *where;

    UINT32   file_num;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hssfs count file num on tcid <tcid> at <where>*/
    /*hssfs count file num on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_count_file_num: hssfs count file num on tcid %s at %s\n",
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_file_num, CMPI_ERROR_MODI, &file_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file num: %ld\n", file_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file num\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_count_file_size(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    uint64_t  file_size;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs count file size of <path> on tcid <tcid> at <where>*/
    /*hssfs count file size of %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_file_size: hssfs count file size of path %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_file_size, CMPI_ERROR_MODI, path_name, &file_size);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] count file size of path %s: %"PRId64"\n", (char *)cstring_get_str(path_name), file_size);
    }
    else
    {
        sys_log(des_log, "[FAIL] count file size of path %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_delete(CMD_PARA_VEC * param)
{
    CSTRING *path_name;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &path_name);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs delete file <file name> on tcid <tcid> at <where>*/
    /*hssfs delete file %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_delete: hssfs delete file %s on tcid %s at %s\n",
                        (char *)cstring_get_str(path_name),
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_delete, CMPI_ERROR_MODI, path_name);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete %s\n", (char *)cstring_get_str(path_name));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete %s\n", (char *)cstring_get_str(path_name));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_show_npp(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hssfs show npp on tcid <tcid> at <where>*/
    /*hssfs show npp on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_show_npp: hssfs show npp on tcid %s at %s\n",
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_show_npp, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(csfsnp_tcid),CMPI_CSFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(csfsnp_tcid),CMPI_CSFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_show_dn(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hssfs show dn on tcid <tcid> at <where>*/
    /*hssfs show dn on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_show_dn: hssfs show dn on tcid %s at %s\n",
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_show_dn, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(csfsnp_tcid),CMPI_CSFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(csfsnp_tcid),CMPI_CSFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_show_cached_np(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*hssfs show cached np on tcid <tcid> at <where>*/
    /*hssfs show cached np on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_show_cached_np: hssfs show cached np on tcid %s at %s\n",
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_show_cached_np, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(csfsnp_tcid),CMPI_CSFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(csfsnp_tcid),CMPI_CSFS_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_csfs_show_specific_np(CMD_PARA_VEC * param)
{
    UINT32   csfsnp_id;
    UINT32   csfsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_uint32(param  , 0, &csfsnp_id);
    api_cmd_para_vec_get_tcid(param    , 1, &csfsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*hssfs show specific np <id> on tcid <tcid> at <where>*/
    /*hssfs show specific np %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_csfs_show_specific_np: hssfs show specific np %ld on tcid %s at %s\n",
                        csfsnp_id,
                        c_word_to_ipv4(csfsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = csfsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_CSFS_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_csfs_show_specific_np, CMPI_ERROR_MODI, csfsnp_id, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC] np %ld\n%s",
                           c_word_to_ipv4(csfsnp_tcid),
                           CMPI_CSFS_RANK,
                           (char *)cstring_get_str(LOG_CSTR(log)),
                           csfsnp_id);
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL] np %ld\n%s",
                          c_word_to_ipv4(csfsnp_tcid),
                          CMPI_CSFS_RANK,
                          (char *)cstring_get_str(LOG_CSTR(log)),
                          csfsnp_id);
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

#endif

#if 1
EC_BOOL api_cmd_ui_ctdns_create_npp(CMD_PARA_VEC * param)
{
    UINT32   ctdnsnp_model;
    UINT32   ctdnsnp_max_num;
    CSTRING *ctdnsnp_db_root_dir;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &ctdnsnp_model);
    api_cmd_para_vec_get_uint32(param  , 1, &ctdnsnp_max_num);
    api_cmd_para_vec_get_cstring(param , 2, &ctdnsnp_db_root_dir);
    api_cmd_para_vec_get_tcid(param    , 3, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*tdns create np model <model> max num <np mum> with root <root dir> on tcid <tcid> at <where>*/
    /*tdns create np model %n max num %n with root %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_create_npp: tdns create np model %ld max num %ld with root %s on tcid %s at %s\n",
                        ctdnsnp_model,
                        ctdnsnp_max_num,
                        (char *)cstring_get_str(ctdnsnp_db_root_dir),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_create_npp, CMPI_ERROR_MODI, ctdnsnp_model, ctdnsnp_max_num,  ctdnsnp_db_root_dir);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] tdns create np model %ld max num %ld with root %s on tcid %s successfully\n",
                        ctdnsnp_model,
                        ctdnsnp_max_num,
                        (char *)cstring_get_str(ctdnsnp_db_root_dir),
                        c_word_to_ipv4(ctdnsnp_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] tdns create np model %ld max num %ld with root %s on tcid %s failed\n",
                        ctdnsnp_model,
                        ctdnsnp_max_num,
                        (char *)cstring_get_str(ctdnsnp_db_root_dir),
                        c_word_to_ipv4(ctdnsnp_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_start(CMD_PARA_VEC * param)
{
    CSTRING *ctdnsnp_root_dir;
    UINT32   ctdnsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_cstring(param , 0, &ctdnsnp_root_dir);
    api_cmd_para_vec_get_tcid(param    , 1, &ctdnsnp_tcid);

    /*tdns start from root <dir> on tcid <tcid>*/
    /*tdns start from root %s on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_start: tdns start from root %s on tcid %s\n",
                        (char *)cstring_get_str(ctdnsnp_root_dir),
                        c_word_to_ipv4(ctdnsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(ctdnsnp_tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*ctdns_md_id = 0*/

    task_act(mod_mgr_def, NULL_PTR, TASK_DEFAULT_LIVE, (UINT32)1, LOAD_BALANCING_LOOP, TASK_PRIO_NORMAL,
             FI_ctdns_start, ctdnsnp_root_dir);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_end(CMD_PARA_VEC * param)
{
    UINT32   ctdnsnp_tcid;

    MOD_MGR   *mod_mgr_def;

    api_cmd_para_vec_get_tcid(param    , 0, &ctdnsnp_tcid);

    /*tdns end on tcid <tcid>*/
    /*tdns end on tcid %t*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_end: tdns close on tcid %s\n",
                        c_word_to_ipv4(ctdnsnp_tcid));

    mod_mgr_def = api_cmd_ui_gen_mod_mgr(ctdnsnp_tcid, CMPI_FWD_RANK, CMPI_ERROR_TCID, CMPI_ERROR_RANK, 0);/*ctdns_md_id = 0*/

    task_dea(mod_mgr_def, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, FI_ctdns_end, CMPI_ERROR_MODI);
    mod_mgr_free(mod_mgr_def);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_config_tcid(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   tcid;
    UINT32   port;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;

    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_tcid(param    , 1, &tcid);
    api_cmd_para_vec_get_uint32(param  , 2, &port);
    api_cmd_para_vec_get_tcid(param    , 3, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*tdns config service <service> tcid <tcid> port <port> on tcid <tcid> at <console|log>*/
    /*tdns config service %s tcid %t port %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_config_tcid: "
                       "tdns config service %s tcid %s port %ld on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        c_word_to_ipv4(tcid),
                        port,
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_config_tcid, CMPI_ERROR_MODI, service, tcid, port);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_ctdns_config_tcid: service '%s', tcid %s, port %ld done\n",
                         (char *)cstring_get_str(service),
                         c_word_to_ipv4(tcid),
                         port);
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_ctdns_config_tcid: service '%s', tcid %s, port %ld failed\n",
                         (char *)cstring_get_str(service),
                         c_word_to_ipv4(tcid),
                         port);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_reserve_tcid(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   ipaddr;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;

    UINT32     tcid;
    UINT32     port;

    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_ipaddr(param  , 1, &ipaddr);
    api_cmd_para_vec_get_tcid(param    , 2, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*tdns reserve service <service> ip <ip> on tcid <tcid> at <console|log>*/
    /*tdns reserve service %s ip %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_reserve_tcid: "
                       "tdns reserve service %s ip %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        c_word_to_ipv4(ipaddr),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_reserve_tcid, CMPI_ERROR_MODI, service, ipaddr, &tcid, &port);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_ctdns_reserve_tcid: service '%s', ip %s => tcid %s port %ld done\n",
                         (char *)cstring_get_str(service),
                         c_word_to_ipv4(ipaddr),
                         c_word_to_ipv4(tcid),
                         port);
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_ctdns_reserve_tcid: service '%s', ip %s => failed\n",
                         (char *)cstring_get_str(service),
                         c_word_to_ipv4(ipaddr));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_release_tcid(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   tcid;
    UINT32   port;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;

    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_tcid(param    , 1, &tcid);
    api_cmd_para_vec_get_uint32(param  , 2, &port);
    api_cmd_para_vec_get_tcid(param    , 3, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*tdns release service <service> tcid <tcid> port <port> on tcid <tcid> at <console|log>*/
    /*tdns release service %s tcid %t port %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_release_tcid: "
                       "tdns release service %s tcid %s port %ld on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        c_word_to_ipv4(tcid),
                        port,
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_release_tcid, CMPI_ERROR_MODI, service, tcid, port);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_ctdns_release_tcid: service '%s', tcid %s port %ld => done\n",
                         (char *)cstring_get_str(service),
                         c_word_to_ipv4(tcid),
                         port);
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_ctdns_release_tcid: service '%s', tcid %s port %ld => failed\n",
                         (char *)cstring_get_str(service),
                         c_word_to_ipv4(tcid),
                         port);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_get_tcid(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    UINT32     ipaddr;
    UINT32     port;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &tcid);
    api_cmd_para_vec_get_tcid(param    , 1, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*tdns get tcid <tcid> on tcid <tcid> at <console|log>*/
    /*tdns get tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_get_tcid: tdns get tcid %s on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_get, CMPI_ERROR_MODI, tcid, &ipaddr, &port);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_ctdns_get_tcid: tcid  %s => ipaddr %s, port %ld\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port);
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_ctdns_get_tcid: get tcid %s failed\n", c_word_to_ipv4(tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_get_service(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   max_num;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_uint32(param  , 1, &max_num);
    api_cmd_para_vec_get_tcid(param    , 2, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*tdns get service <service> max nodes <num> on tcid <tcid> at <console|log>*/
    /*tdns get service %s max nodes %n on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_get_service: tdns get service %s max nodes %ld on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        max_num,
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_finger_service, CMPI_ERROR_MODI, service, max_num, ctdnssv_node_mgr);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] api_cmd_ui_ctdns_get_service:\n");
        ctdnssv_node_mgr_print(des_log, ctdnssv_node_mgr);
    }
    else
    {
        sys_log(des_log, "[FAIL] api_cmd_ui_ctdns_get_service: failed\n");
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_set_no_service(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   ipaddr;
    UINT32   port;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &tcid);
    api_cmd_para_vec_get_ipaddr(param  , 1, &ipaddr);
    api_cmd_para_vec_get_uint32(param  , 2, &port);
    api_cmd_para_vec_get_tcid(param    , 3, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*tdns set tcid <tcid> ip <ip> port <port> [service <service>] on tcid <tcid> at <console|log>*/
    /*tdns set tcid %t ip %t port %n [service %s] on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_set_no_service: tdns set tcid %s ip %s port %ld on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        c_word_to_ipv4(ipaddr),
                        port,
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_set_no_service, CMPI_ERROR_MODI, tcid, ipaddr, port);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] tcid %s, ipaddr %s, port %ld\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port);
    }
    else
    {
        sys_log(des_log, "[FAIL] tcid %s, ipaddr %s, port %ld\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_set_has_service(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   ipaddr;
    UINT32   port;
    CSTRING *service;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &tcid);
    api_cmd_para_vec_get_ipaddr(param  , 1, &ipaddr);
    api_cmd_para_vec_get_uint32(param  , 2, &port);
    api_cmd_para_vec_get_cstring(param , 3, &service);
    api_cmd_para_vec_get_tcid(param    , 4, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*tdns set tcid <tcid> ip <ip> port <port> [service <service>] on tcid <tcid> at <console|log>*/
    /*tdns set tcid %t ip %t port %n [service %s] on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_set_has_service: tdns set tcid %s ip %s port %ld service %s on tcid %s at %s\n",
                                        c_word_to_ipv4(tcid),
                                        c_word_to_ipv4(ipaddr),
                                        port,
                                        (char *)cstring_get_str(service),
                                        c_word_to_ipv4(ctdnsnp_tcid),
                                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_set, CMPI_ERROR_MODI, tcid, ipaddr, port, service);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] tcid %s, ipaddr %s, port %ld, service %s\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port,
                         (char *)cstring_get_str(service));
    }
    else
    {
        sys_log(des_log, "[FAIL] tcid %s, ipaddr %s, port %ld, service %s\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port,
                         (char *)cstring_get_str(service));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_search_tcid(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &tcid);
    api_cmd_para_vec_get_tcid(param    , 1, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*tdns search tcid <tcid> on tcid <tcid> at <console|log>*/
    /*tdns search tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_search_tcid: tdns search tcid %s on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_exists_tcid, CMPI_ERROR_MODI, tcid);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", c_word_to_ipv4(tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", c_word_to_ipv4(tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_search_service(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_tcid(param    , 1, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*tdns search service <service> on tcid <tcid> at <console|log>*/
    /*tdns search service %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_search_tcid: tdns search service %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_exists_service, CMPI_ERROR_MODI, service);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] search %s\n", (char *)cstring_get_str(service));
    }
    else
    {
        sys_log(des_log, "[FAIL] search %s\n", (char *)cstring_get_str(service));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_count_tcid_num(CMD_PARA_VEC * param)
{
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    UINT32   tcid_num;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*tdns count tcid num on tcid <tcid> at <console|log>*/
    /*tdns count tcid num on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_count_tcid_num: tdns count tcid num on tcid %s at %s\n",
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_tcid_num, CMPI_ERROR_MODI, &tcid_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] tcid num: %ld\n", tcid_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] tcid num\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_count_node_num(CMD_PARA_VEC * param)
{
    UINT32   ctdnsnp_tcid;
    CSTRING *service;
    CSTRING *where;

    UINT32   node_num;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_tcid(param    , 1, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*tdns count service <service> node num on tcid <tcid> at <console|log>*/
    /*tdns count service %s node num on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_count_node_num: "
                        "tdns count service %s node num on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_node_num, CMPI_ERROR_MODI, service, &node_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] node num: %ld\n", node_num);
    }
    else
    {
        sys_log(des_log, "[FAIL] node num\n");
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_delete(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_tcid(param    , 0, &tcid);
    api_cmd_para_vec_get_tcid(param    , 1, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*tdns delete tcid <tcid> on tcid <tcid> at <console|log>*/
    /*tdns delete tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_delete: tdns delete tcid %s on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_delete, CMPI_ERROR_MODI, tcid);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] delete %s\n", c_word_to_ipv4(tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] delete %s\n", c_word_to_ipv4(tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_online(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   network;
    UINT32   tdns_tcid;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_uint32(param  , 1, &network);
    api_cmd_para_vec_get_tcid(param    , 2, &tdns_tcid);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*tdns online service <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>*/
    /*tdns online service %s network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_online: tdns online service %s network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        network,
                        c_word_to_ipv4(tdns_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_online, CMPI_ERROR_MODI, network, tdns_tcid, service);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] online %s\n", c_word_to_ipv4(tdns_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] online %s\n", c_word_to_ipv4(tdns_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_offline(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   network;
    UINT32   tdns_tcid;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_uint32(param  , 1, &network);
    api_cmd_para_vec_get_tcid(param    , 2, &tdns_tcid);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*tdns offline service <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>*/
    /*tdns offline service %s network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_offline: tdns offline service %s network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        network,
                        c_word_to_ipv4(tdns_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_offline, CMPI_ERROR_MODI, network, tdns_tcid, service);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] offline %s\n", c_word_to_ipv4(tdns_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] offline %s\n", c_word_to_ipv4(tdns_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_show_npp(CMD_PARA_VEC * param)
{
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*tdns show npp on tcid <tcid> at <where>*/
    /*tdns show npp on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_show_npp: tdns show npp on tcid %s at %s\n",
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_show_npp, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(ctdnsnp_tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(ctdnsnp_tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_show_svp(CMD_PARA_VEC * param)
{
    UINT32   ctdnsnp_tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &ctdnsnp_tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*tdns show svp on tcid <tcid> at <where>*/
    /*tdns show svp on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_show_svp: tdns show svp on tcid %s at %s\n",
                        c_word_to_ipv4(ctdnsnp_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = ctdnsnp_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_show_svp, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(ctdnsnp_tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(ctdnsnp_tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_ctdns_refresh_cache(CMD_PARA_VEC * param)
{
    CSTRING *cache_path;
    CSTRING *service;
    UINT32   network;
    UINT32   tdns_tcid;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &cache_path);
    api_cmd_para_vec_get_cstring(param , 1, &service);
    api_cmd_para_vec_get_uint32(param  , 2, &network);
    api_cmd_para_vec_get_tcid(param    , 3, &tdns_tcid);
    api_cmd_para_vec_get_tcid(param    , 4, &tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*tdns refresh path <cache path> service <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>*/
    /*tdns refresh path %s service %s network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_ctdns_refresh_cache: tdns refresh path %s service %s network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(cache_path),
                        (char *)cstring_get_str(service),
                        network,
                        c_word_to_ipv4(tdns_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_refresh_cache, CMPI_ERROR_MODI, network, tdns_tcid, service, cache_path);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] refresh %s\n", c_word_to_ipv4(tdns_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] refresh %s\n", c_word_to_ipv4(tdns_tcid));
    }

    return (EC_TRUE);
}
#endif

#if 1
EC_BOOL api_cmd_ui_cdetect_show_orig_nodes(CMD_PARA_VEC * param)
{
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_tcid(param    , 0, &tcid);
    api_cmd_para_vec_get_cstring(param , 1, &where);

    /*detect show orig nodes on tcid <tcid> at <where>*/
    /*detect show orig nodes on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cdetect_show_orig_nodes: detect show orig nodes on tcid %s at %s\n",
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cdetect_show_orig_nodes, CMPI_ERROR_MODI, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cdetect_show_orig_node(CMD_PARA_VEC * param)
{
    CSTRING *domain;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    LOG *log;
    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &domain);
    api_cmd_para_vec_get_tcid(param    , 1, &tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*detect show orig node <domain> on tcid <tcid> at <where>*/
    /*detect show orig node %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cdetect_show_orig_node: detect show orig node %s on tcid %s at %s\n",
                        (char *)cstring_get_str(domain),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;
    log = log_cstr_open();

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cdetect_show_orig_node, CMPI_ERROR_MODI, domain, log);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n%s", c_word_to_ipv4(tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n%s", c_word_to_ipv4(tcid),CMPI_FWD_RANK, (char *)cstring_get_str(LOG_CSTR(log)));
        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cdetect_dns_resolve(CMD_PARA_VEC * param)
{
    CSTRING *domain;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    UINT32     ipaddr;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &domain);
    api_cmd_para_vec_get_tcid(param    , 1, &tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*detect dns resolve domain <domain> on tcid <tcid> at <where>*/
    /*detect dns resolve domain %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cdetect_dns_resolve: detect dns resolve domain %s on tcid %s at %s\n",
                        (char *)cstring_get_str(domain),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cdetect_dns_resolve, CMPI_ERROR_MODI, domain, &ipaddr);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
        sys_log(des_log, "ip: %s\n", c_word_to_ipv4(ipaddr));
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cdetect_process(CMD_PARA_VEC * param)
{
    UINT32   task_max_num;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_uint32(param  , 0, &task_max_num);
    api_cmd_para_vec_get_tcid(param    , 1, &tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*detect process <num> tasks on tcid <tcid> at <where>*/
    /*detect process %n tasks on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cdetect_process: detect process %ld tasks on tcid %s at %s\n",
                        task_max_num,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cdetect_process, CMPI_ERROR_MODI, task_max_num);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cdetect_process_loop(CMD_PARA_VEC * param)
{
    UINT32   task_max_num;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    api_cmd_para_vec_get_uint32(param  , 0, &task_max_num);
    api_cmd_para_vec_get_tcid(param    , 1, &tcid);
    api_cmd_para_vec_get_cstring(param , 2, &where);

    /*detect loop process <num> tasks on tcid <tcid> at <where>*/
    /*detect loop process %n tasks on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cdetect_process_loop: detect loop process %ld tasks on tcid %s at %s\n",
                        task_max_num,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &mod_node,
             NULL_PTR,
             FI_cdetect_process_loop, CMPI_ERROR_MODI, task_max_num);

    des_log = api_cmd_ui_get_log(where);

    sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);

    return (EC_TRUE);
}
#endif

#if 1
EC_BOOL api_cmd_ui_cp2p_load(CMD_PARA_VEC * param)
{
    CSTRING *src_file;
    CSTRING *service;
    CSTRING *des_file;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &src_file);
    api_cmd_para_vec_get_cstring(param , 1, &service);
    api_cmd_para_vec_get_cstring(param , 2, &des_file);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p upload <src file> to <service> <des file> on tcid <tcid> at <where>*/
    /*p2p upload %s to %s %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_load: p2p upload %s to %s %s on tcid %s at %s\n",
                        (char *)cstring_get_str(src_file),
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(des_file),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cp2p_file_load, CMPI_ERROR_MODI, src_file, service, des_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_upload(CMD_PARA_VEC * param)
{
    CSTRING *src_file;
    CSTRING *service;
    CSTRING *des_file;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    CBYTES    *src_file_content;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &src_file);
    api_cmd_para_vec_get_cstring(param , 1, &service);
    api_cmd_para_vec_get_cstring(param , 2, &des_file);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p upload <src file> to <service> <des file> to tcid <tcid> at <where>*/
    /*p2p upload %s to %s %s to tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_upload: p2p upload %s to %s %s to tcid %s at %s\n",
                        (char *)cstring_get_str(src_file),
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(des_file),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    src_file_content = c_file_load_whole((char *)cstring_get_str(src_file));
    if(NULL_PTR == src_file_content)
    {
        des_log = api_cmd_ui_get_log(where);

        sys_log(des_log, "[rank_%s_%ld] error:load local file '%s' failed\n",
                         c_word_to_ipv4(tcid),CMPI_FWD_RANK,
                         (char *)cstring_get_str(src_file));

        return (EC_TRUE);
    }

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_cp2p_file_upload, CMPI_ERROR_MODI, src_file_content, service, des_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cbytes_free(src_file_content);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __api_cmd_ui_cp2p_fetch_size(CP2P_FILE  *cp2p_file, const UINT32 tcid)
{
    CSTRING    rfs_file_path;
    MOD_NODE   recv_mod_node;
    uint64_t   file_size;

    EC_BOOL    ret;

    cstring_init(&rfs_file_path, NULL_PTR);
    cstring_format(&rfs_file_path, "/%s%s", CP2P_FILE_SERVICE_NAME_STR(cp2p_file), CP2P_FILE_SRC_NAME_STR(cp2p_file));

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_crfs_file_size, CMPI_ERROR_MODI, &rfs_file_path, &file_size);
    ASSERT(EC_TRUE == ret);
    CP2P_FILE_SRC_SIZE(cp2p_file) = (UINT32)file_size;

    cstring_clean(&rfs_file_path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __api_cmd_ui_cp2p_fetch_md5(CP2P_FILE  *cp2p_file, const UINT32 tcid)
{
    CSTRING    rfs_file_path;
    MOD_NODE   recv_mod_node;

    EC_BOOL    ret;

    cstring_init(&rfs_file_path, NULL_PTR);
    cstring_format(&rfs_file_path, "/%s%s", CP2P_FILE_SERVICE_NAME_STR(cp2p_file), CP2P_FILE_SRC_NAME_STR(cp2p_file));

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_crfs_file_md5sum, CMPI_ERROR_MODI, &rfs_file_path, CP2P_FILE_SRC_MD5(cp2p_file));
    ASSERT(EC_TRUE == ret);

    cstring_clean(&rfs_file_path);
    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_push(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    UINT32   des_network;
    UINT32   des_tcid;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_uint32(param  , 2, &des_network);
    api_cmd_para_vec_get_tcid(param    , 3, &des_tcid);
    api_cmd_para_vec_get_tcid(param    , 4, &tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*p2p push <service> <src file> to network <network> tcid <tcid> on tcid <tcid> at <where>*/
    /*p2p push %s %s to network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_push: "
                        "p2p push %s %s to network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        des_network,
                        c_word_to_ipv4(des_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    __api_cmd_ui_cp2p_fetch_size(&cp2p_file, tcid);
    __api_cmd_ui_cp2p_fetch_md5(&cp2p_file, tcid);
    cp2p_file_print(LOGCONSOLE, &cp2p_file);

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_push, CMPI_ERROR_MODI, des_network, des_tcid, &cp2p_file);


    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_push_subnet(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    UINT32   des_network;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_uint32(param  , 2, &des_network);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p push <service> <src file> to network <network> tcid <tcid> on tcid <tcid> at <where>*/
    /*p2p push %s %s to network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_push_subnet: "
                        "p2p push %s %s to network %ld all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        des_network,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    __api_cmd_ui_cp2p_fetch_size(&cp2p_file, tcid);
    __api_cmd_ui_cp2p_fetch_md5(&cp2p_file, tcid);

    cp2p_file_print(LOGCONSOLE, &cp2p_file);

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_push, CMPI_ERROR_MODI, des_network, CMPI_ANY_TCID, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_push_all(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_tcid(param    , 2, &tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*p2p push <service> <src file> to network <network> tcid <tcid> on tcid <tcid> at <where>*/
    /*p2p push %s %s to network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_push_all: "
                        "p2p push %s %s to all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    __api_cmd_ui_cp2p_fetch_size(&cp2p_file, tcid);
    __api_cmd_ui_cp2p_fetch_md5(&cp2p_file, tcid);
    cp2p_file_print(LOGCONSOLE, &cp2p_file);

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_push, CMPI_ERROR_MODI, CMPI_ANY_NETWORK, CMPI_ANY_TCID, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_pull(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_tcid(param    , 2, &tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*p2p pull <service> <src file> on tcid <tcid> at <where>*/
    /*p2p pull %s %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_pull: "
                        "p2p pull %s %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_pull, CMPI_ERROR_MODI, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_delete(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    UINT32   des_network;
    UINT32   des_tcid;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_uint32(param  , 2, &des_network);
    api_cmd_para_vec_get_tcid(param    , 3, &des_tcid);
    api_cmd_para_vec_get_tcid(param    , 4, &tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*p2p delete <service> <src file> in network <network> tcid <tcid> on tcid <tcid> at <where>*/
    /*p2p delete %s %s in network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_delete: "
                        "p2p delete %s %s in network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        des_network,
                        c_word_to_ipv4(des_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_delete, CMPI_ERROR_MODI, des_network, des_tcid, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_delete_subnet(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    UINT32   des_network;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_uint32(param  , 2, &des_network);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p delete <service> <src file> in network <network> all on tcid <tcid> at <where>*/
    /*p2p delete %s %s in network %n all on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_delete_subnet: "
                        "p2p delete %s %s in network %ld all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        des_network,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_delete, CMPI_ERROR_MODI, des_network, CMPI_ANY_TCID, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_delete_all(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_tcid(param    , 2, &tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*p2p delete <service> <src file> all on tcid <tcid> at <where>*/
    /*p2p delete %s %s all on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_delete_all: "
                        "p2p delete %s %s in all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_delete, CMPI_ERROR_MODI, CMPI_ANY_NETWORK, CMPI_ANY_TCID, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_flush(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    CSTRING *des_file;
    UINT32   des_network;
    UINT32   des_tcid;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_cstring(param , 2, &des_file);
    api_cmd_para_vec_get_uint32(param  , 3, &des_network);
    api_cmd_para_vec_get_tcid(param    , 4, &des_tcid);
    api_cmd_para_vec_get_tcid(param    , 5, &tcid);
    api_cmd_para_vec_get_cstring(param , 6, &where);

    /*p2p flush <service> <src file> to <des file> in network <network> tcid <tcid> on tcid <tcid> at <where>*/
    /*p2p flush %s %s to %s in network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_flush: "
                        "p2p flush %s %s to %s in network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        (char *)cstring_get_str(des_file),
                        des_network,
                        c_word_to_ipv4(des_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    cstring_clone(des_file, CP2P_FILE_DES_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    __api_cmd_ui_cp2p_fetch_size(&cp2p_file, tcid);
    __api_cmd_ui_cp2p_fetch_md5(&cp2p_file, tcid);
    cp2p_file_print(LOGCONSOLE, &cp2p_file);

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_flush, CMPI_ERROR_MODI, des_network, des_tcid, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_flush_subnet(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    CSTRING *des_file;
    UINT32   des_network;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_cstring(param , 2, &des_file);
    api_cmd_para_vec_get_uint32(param  , 3, &des_network);
    api_cmd_para_vec_get_tcid(param    , 4, &tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*p2p flush <service> <src file> to <des file> in network <network> all on tcid <tcid> at <where>*/
    /*p2p flush %s %s to %s in network %n all on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_flush_subnet: "
                        "p2p flush %s %s to %s in network %ld all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        (char *)cstring_get_str(des_file),
                        des_network,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    cstring_clone(des_file, CP2P_FILE_DES_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    __api_cmd_ui_cp2p_fetch_size(&cp2p_file, tcid);
    __api_cmd_ui_cp2p_fetch_md5(&cp2p_file, tcid);
    cp2p_file_print(LOGCONSOLE, &cp2p_file);

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_flush, CMPI_ERROR_MODI, des_network, CMPI_ANY_TCID, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_flush_all(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    CSTRING *des_file;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_cstring(param , 2, &des_file);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p flush <service> <src file> to <des file> in all on tcid <tcid> at <where>*/
    /*p2p flush %s %s to %s in all on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_flush_all: "
                        "p2p flush %s %s to %s in all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        (char *)cstring_get_str(des_file),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    cstring_clone(des_file, CP2P_FILE_DES_NAME(&cp2p_file));
    CP2P_FILE_REPORT_TCID(&cp2p_file) = tcid;

    __api_cmd_ui_cp2p_fetch_size(&cp2p_file, tcid);
    __api_cmd_ui_cp2p_fetch_md5(&cp2p_file, tcid);
    cp2p_file_print(LOGCONSOLE, &cp2p_file);

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_flush, CMPI_ERROR_MODI, CMPI_ANY_NETWORK, CMPI_ANY_TCID, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_download(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *src_file;
    UINT32   src_tcid;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_FILE  cp2p_file;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &src_file);
    api_cmd_para_vec_get_tcid(param    , 2, &src_tcid);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p download <service> <src file> from <tcid> on tcid <tcid> at <where>*/
    /*p2p download %s %s from <tcid> on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_download: "
                        "p2p download %s %s from %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(src_file),
                        c_word_to_ipv4(src_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_file_init(&cp2p_file);
    cstring_clone(service , CP2P_FILE_SERVICE_NAME(&cp2p_file));
    cstring_clone(src_file, CP2P_FILE_SRC_NAME(&cp2p_file));
    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_file_download, CMPI_ERROR_MODI, src_tcid, &cp2p_file);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_file_clean(&cp2p_file);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_execute_cmd(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *command;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_CMD   cp2p_cmd;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &command);
    api_cmd_para_vec_get_tcid(param    , 2, &tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*p2p execute <service> <cmd> on tcid <tcid> at <where>*/
    /*p2p execute %s %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_execute_cmd: "
                        "p2p execute %s %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(command),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_cmd_init(&cp2p_cmd);
    cstring_clone(service, CP2P_CMD_SERVICE_NAME(&cp2p_cmd));
    cstring_clone(command, CP2P_CMD_COMMAND_LINE(&cp2p_cmd));
    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_cmd_execute, CMPI_ERROR_MODI, &cp2p_cmd);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_cmd_clean(&cp2p_cmd);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_deliver_cmd(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *command;
    UINT32   des_network;
    UINT32   des_tcid;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_CMD   cp2p_cmd;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &command);
    api_cmd_para_vec_get_uint32(param  , 2, &des_network);
    api_cmd_para_vec_get_tcid(param    , 3, &des_tcid);
    api_cmd_para_vec_get_tcid(param    , 4, &tcid);
    api_cmd_para_vec_get_cstring(param , 5, &where);

    /*p2p deliver <service> <cmd> in network <network> tcid <tcid> on tcid <tcid> at <where>*/
    /*p2p deliver %s %s in network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_deliver_cmd: "
                        "p2p deliver %s %s in network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(command),
                        des_network,
                        c_word_to_ipv4(des_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_cmd_init(&cp2p_cmd);
    cstring_clone(service, CP2P_CMD_SERVICE_NAME(&cp2p_cmd));
    cstring_clone(command, CP2P_CMD_COMMAND_LINE(&cp2p_cmd));
    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_cmd_deliver, CMPI_ERROR_MODI, des_network, des_tcid, &cp2p_cmd);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_cmd_clean(&cp2p_cmd);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_deliver_cmd_subnet(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *command;
    UINT32   des_network;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_CMD   cp2p_cmd;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &command);
    api_cmd_para_vec_get_uint32(param  , 2, &des_network);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p deliver <service> <cmd> in network <network> all on tcid <tcid> at <where>*/
    /*p2p deliver %s %s in network %n all on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_deliver_cmd_subnet: "
                        "p2p deliver %s %s in network %ld all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(command),
                        des_network,
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_cmd_init(&cp2p_cmd);
    cstring_clone(service, CP2P_CMD_SERVICE_NAME(&cp2p_cmd));
    cstring_clone(command, CP2P_CMD_COMMAND_LINE(&cp2p_cmd));
    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_cmd_deliver, CMPI_ERROR_MODI, des_network, CMPI_ANY_TCID, &cp2p_cmd);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_cmd_clean(&cp2p_cmd);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_deliver_cmd_all(CMD_PARA_VEC * param)
{
    CSTRING *service;
    CSTRING *command;

    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   recv_mod_node;
    CP2P_CMD   cp2p_cmd;

    LOG       *des_log;

    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_cstring(param , 1, &command);
    api_cmd_para_vec_get_tcid(param    , 2, &tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*p2p deliver <service> <cmd> in all on tcid <tcid> at <where>*/
    /*p2p deliver %s %s in all on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_deliver_cmd_all: "
                        "p2p deliver %s %s in all on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        (char *)cstring_get_str(command),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    cp2p_cmd_init(&cp2p_cmd);
    cstring_clone(service, CP2P_CMD_SERVICE_NAME(&cp2p_cmd));
    cstring_clone(command, CP2P_CMD_COMMAND_LINE(&cp2p_cmd));
    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cp2p_cmd_deliver, CMPI_ERROR_MODI, CMPI_ANY_NETWORK, CMPI_ANY_TCID, &cp2p_cmd);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[rank_%s_%ld][SUCC]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }
    else
    {
        sys_log(des_log, "[rank_%s_%ld][FAIL]\n", c_word_to_ipv4(tcid),CMPI_FWD_RANK);
    }

    cp2p_cmd_clean(&cp2p_cmd);

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_online(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   network;
    UINT32   p2p_tcid;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_uint32(param  , 1, &network);
    api_cmd_para_vec_get_tcid(param    , 2, &p2p_tcid);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p online <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>*/
    /*p2p online %s network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_online: p2p online service %s network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        network,
                        c_word_to_ipv4(p2p_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_online, CMPI_ERROR_MODI, network, p2p_tcid, service);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] online %s\n", c_word_to_ipv4(p2p_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] online %s\n", c_word_to_ipv4(p2p_tcid));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_cp2p_offline(CMD_PARA_VEC * param)
{
    CSTRING *service;
    UINT32   network;
    UINT32   p2p_tcid;
    UINT32   tcid;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;
    EC_BOOL    ret;

    api_cmd_para_vec_get_cstring(param , 0, &service);
    api_cmd_para_vec_get_uint32(param  , 1, &network);
    api_cmd_para_vec_get_tcid(param    , 2, &p2p_tcid);
    api_cmd_para_vec_get_tcid(param    , 3, &tcid);
    api_cmd_para_vec_get_cstring(param , 4, &where);

    /*p2p offline <service> network <network> tcid <tcid> on tcid <tcid> at <console|log>*/
    /*p2p offline %s network %n tcid %t on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_cp2p_offline: p2p offline %s network %ld tcid %s on tcid %s at %s\n",
                        (char *)cstring_get_str(service),
                        network,
                        c_word_to_ipv4(p2p_tcid),
                        c_word_to_ipv4(tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_ctdns_offline, CMPI_ERROR_MODI, network, p2p_tcid, service);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] offline %s\n", c_word_to_ipv4(p2p_tcid));
    }
    else
    {
        sys_log(des_log, "[FAIL] offline %s\n", c_word_to_ipv4(p2p_tcid));
    }

    return (EC_TRUE);
}

#endif

EC_BOOL api_cmd_ui_download_file(CMD_PARA_VEC * param)
{
    UINT32   super_tcid;
    CSTRING *src_fname;
    CSTRING *des_fname;
    CSTRING *where;

    MOD_NODE   mod_node;
    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &src_fname);
    api_cmd_para_vec_get_cstring(param , 1, &des_fname);
    api_cmd_para_vec_get_tcid(param    , 2, &super_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*download file <src fname> to <des fname> from tcid <tcid>  at <console|log>*/
    /*download file %s to %s from tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_download_file: download file %s to %s from tcid %s at %s\n",
                        (char *)cstring_get_str(src_fname),
                        (char *)cstring_get_str(des_fname),
                        c_word_to_ipv4(super_tcid),
                        (char *)cstring_get_str(where));

    MOD_NODE_TCID(&mod_node) = super_tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = 0;
    MOD_NODE_MODI(&mod_node) = 0;

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_super_transfer, CMPI_ERROR_MODI, src_fname, CMPI_LOCAL_TCID, des_fname);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] %s:%s -> %s:%s\n",
                           c_word_to_ipv4(super_tcid),
                           (char *)cstring_get_str(src_fname),
                           c_word_to_ipv4(CMPI_LOCAL_TCID),
                           (char *)cstring_get_str(des_fname));
    }
    else
    {
        sys_log(des_log, "[FAIL] %s:%s -> %s:%s\n",
                           c_word_to_ipv4(super_tcid),
                           (char *)cstring_get_str(src_fname),
                           c_word_to_ipv4(CMPI_LOCAL_TCID),
                           (char *)cstring_get_str(des_fname));
    }

    return (EC_TRUE);
}

EC_BOOL api_cmd_ui_upload_file(CMD_PARA_VEC * param)
{
    UINT32   super_tcid;
    CSTRING *src_fname;
    CSTRING *des_fname;
    CSTRING *where;

    LOG       *des_log;

    EC_BOOL   ret;

    api_cmd_para_vec_get_cstring(param , 0, &src_fname);
    api_cmd_para_vec_get_cstring(param , 1, &des_fname);
    api_cmd_para_vec_get_tcid(param    , 2, &super_tcid);
    api_cmd_para_vec_get_cstring(param , 3, &where);

    /*upload file <src fname> to <des fname> on tcid <tcid>  at <console|log>*/
    /*upload file %s to %s on tcid %t at %s*/
    dbg_log(SEC_0010_API, 9)(LOGSTDOUT, "[DEBUG] api_cmd_ui_download_file: upload file %s to %s on tcid %s at %s\n",
                        (char *)cstring_get_str(src_fname),
                        (char *)cstring_get_str(des_fname),
                        c_word_to_ipv4(super_tcid),
                        (char *)cstring_get_str(where));

    ret = super_transfer(0, src_fname, super_tcid, des_fname);

    des_log = api_cmd_ui_get_log(where);

    if(EC_TRUE == ret)
    {
        sys_log(des_log, "[SUCC] %s:%s -> %s:%s\n",
                           c_word_to_ipv4(CMPI_LOCAL_TCID),
                           (char *)cstring_get_str(src_fname),
                           c_word_to_ipv4(super_tcid),
                           (char *)cstring_get_str(des_fname));
    }
    else
    {
        sys_log(des_log, "[FAIL] %s:%s -> %s:%s\n",
                           c_word_to_ipv4(CMPI_LOCAL_TCID),
                           (char *)cstring_get_str(src_fname),
                           c_word_to_ipv4(super_tcid),
                           (char *)cstring_get_str(des_fname));
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

