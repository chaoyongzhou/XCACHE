#! /usr/bin/perl -w

###############################################################################
#
#   Copyright (C) Chaoyong Zhou
#   Email: bgnvendor@163.com
#   QQ: 2796796
#
################################################################################

use strict;

my $g_autoflush_flag;
my $g_usage =
    "$0 config=<sys config xml> tag=<xfs|ngx> [ips=<ip[,ip]|all>] [ports=<port|port-port[,port|port-port]>] [verbose=on|off]";

my %g_err_code =
(
    "no_err"        =>   0,#
    "err_repeat_id" =>   2,#
    "err_keyword"   =>   4,#
    "err_hash_key"  =>   8,#
    "err_args"      =>  16,#
    "err_seq_str"   =>  20,#
    "err_ciphertxt" =>  24,#
    "err_plaintxt"  =>  25,#
    "err_ftp"       =>  32,#
    "err_telnet"    =>  48,#
    "err_no_file"   =>  64,#
    "err_no_dn"     =>  72,#
    "err_open_file" =>  80,#
    "err_read_file" =>  96,#
    "err_write_file"=> 112,#
    "err_cm_parser" => 128,#
    "err_undef"     => 110,#

);

my $g_config_xml;
my $g_tag;
my $g_ip_addr_list;
my $g_port_range;
my $g_verbose;

my $g_sys_config = {};
my $g_paras_config = {};

#my $g_xfs_bgn_port_range = "618-629";
#my $g_ngx_bgn_port_range = "818-829,838-849,858-869,878-889";

&fetch_config($g_paras_config, @ARGV);
&check_config($g_paras_config, $g_usage);
#&print_config($g_paras_config);

$g_config_xml = $$g_paras_config{"config"};
if( ! -f $g_config_xml )
{
    &com_err("error: $g_config_xml not exist\n");
    &com_die(2, "usage: $g_usage\n");
}

$g_tag          = $$g_paras_config{"tag"};
$g_ip_addr_list = $$g_paras_config{"ips"}     || undef;
$g_port_range   = $$g_paras_config{"ports"}   || undef;
$g_verbose      = $$g_paras_config{"verbose"} || undef;

&open_fp_autoflush(\*STDOUT);

&sys_config_xml_parse($g_config_xml, $g_sys_config);

&sys_config_filter(\*STDOUT, $g_sys_config, $g_ip_addr_list, $g_port_range, $g_tag);

&restore_fp_autoflush(\*STDOUT);


########################################################################################################################
# tasks_config_print($fp, %tasks_config, $tag)
########################################################################################################################
sub tasks_config_print
{
    my $fp;
    my $tasks_config;
    my $tag;

    my $segs;

    ($fp, $tasks_config, $tag) = @_;

    $segs = [];
    &arr_push_no_space($segs, $tag);
    &arr_push_no_space($segs, $$tasks_config{"tcid"});
    &arr_push_no_space($segs, $$tasks_config{"maski"});
    &arr_push_no_space($segs, $$tasks_config{"maske"});
    &arr_push_no_space($segs, $$tasks_config{"srvport"});
    &arr_push_no_space($segs, $$tasks_config{"csrvport"});
    &arr_push_no_space($segs, $$tasks_config{"srvipaddr"});
    &arr_push_no_space($segs, $$tasks_config{"cluster"});

    printf $fp ("%s\n", join(",", @$segs));
}

########################################################################################################################
# sys_config_filter($fp, %sys_config, $ip_addr_range, $port_range, $tag)
########################################################################################################################
sub sys_config_filter
{
    my $fp;
    my $sys_config;
    my $ip_addr_range;
    my $port_range;
    my $tag;

    my $ip_addr_list;
    my $ip_addr;

    my $port_list;
    my $port;

    my $task_config;
    my $tasks_config;

    ($fp, $sys_config, $ip_addr_range, $port_range, $tag) = @_;

    if(defined($ip_addr_range) && $ip_addr_range ne "" && $ip_addr_range ne "all")
    {
        $ip_addr_list = [];
        @$ip_addr_list = split(/,/, $ip_addr_range);
        &com_die("err_args", "ip_addr_list is empty\n") if (0 == scalar(@$ip_addr_list));
    }

    if(defined($port_range) && $port_range ne "" && $port_range ne "all")
    {
        $port_list = [];
        &port_range_parse($port_range, $port_list);
        &com_die("err_args", "port_list is empty\n") if (0 == scalar(@$port_list));
    }

    $task_config = $$sys_config{"taskConfig"};
    foreach $tasks_config (@$task_config)
    {
        #if($$tasks_config{"srvipaddr"} ~~ @$ip_addr_list
        #&& $$tasks_config{"srvport"} ~~ @$port_list)
        #{
        #    &tasks_config_print($fp, $tasks_config, $tag);
        #}

        next if(defined($ip_addr_list)
             && 0 != &arr_check_exist($ip_addr_list, $$tasks_config{"srvipaddr"}));

        next if(defined($port_list)
             && 0 != &arr_check_exist($port_list, $$tasks_config{"srvport"}));

        &tasks_config_print($fp, $tasks_config, $tag);
    }
}

########################################################################################################################
# port_range_parse($port_range, @port_list)
########################################################################################################################
sub port_range_parse
{
    my $port_range;
    my $port_list;

    my @port_range_segs;
    my $port_range_seg;

    my $port_range_beg;
    my $port_range_end;
    my $port;

    ($port_range, $port_list) = @_;

    @port_range_segs = split(/,/, $port_range);

    foreach $port_range_seg (@port_range_segs)
    {
        ($port_range_beg, $port_range_end) = split(/-/, $port_range_seg);
        $port_range_end = $port_range_beg if(! defined($port_range_end));

        for($port = $port_range_beg; $port <= $port_range_end; $port ++)
        {
            push(@$port_list, $port);
        }
    }

    return;
}

########################################################################################################################
# arr_push_no_space($arr, $str)
########################################################################################################################
sub arr_push_no_space
{
    my $arr;
    my $str;

    ($arr, $str) = @_;

    if(defined($str))
    {
        push(@$arr, $str);
    }
    else
    {
        push(@$arr, "");
    }
}

########################################################################################################################
# arr_check_exist($arr, $str)
########################################################################################################################
sub arr_check_exist
{
    my $arr;
    my $str;

    my $key;

    ($arr, $str) = @_;

    foreach $key (@$arr)
    {
        if($key eq $str)
        {
            return 0; # exist
        }
    }
    return 1; # not exist
}

########################################################################################################################
# skip_comments($src_template_xml)
########################################################################################################################
sub skip_comments
{
    my $src_template_xml;

    my $line;

    ($src_template_xml) = @_;

    $line = "";
    while( <$src_template_xml> )
    {
        if($_ =~ /-->/)
        {
            $line = $_;
            $line =~ s/.*-->//g;

            last;
        }
    }
    return $line;
}

########################################################################################################################
# tasks_config_parse($line, @task_config)
########################################################################################################################
sub tasks_config_parse
{
    my $line;
    my $task_config;

    my $tasks_config;

    my $tcid;
    my $maski;
    my $maske;
    my $srvipaddr;
    my $srvport;
    my $csrvport;
    my $cluster;

    my @cluster_segs;
    my $cluster_seg;
    my @cluster_seg_ids;
    my $cluster_seg_ids_num;
    my @cluster_ids;
    my $cluster_id;
    my $cluster_beg;
    my $cluster_end;

    my $tcid_beg;
    my $srvipaddr_beg;
    my $srvport_beg;
    my $csrvport_beg;

    my $tcid_end;
    my $srvipaddr_end;
    my $srvport_end;
    my $csrvport_end;

    ($line, $task_config) = @_;

    chomp($line);

    if($line =~ /tcid=\"(\d+).(\d+).(\d+).(\d+)-(\d+)\"/)
    {
        $tcid_beg = ($1 << 24) | ($2 << 16) | ($3 << 8) | ($4 << 0);
        $tcid_end = ($1 << 24) | ($2 << 16) | ($3 << 8) | ($5 << 0);
    }
    elsif($line =~ /tcid=\"(\d+).(\d+).(\d+).(\d+)\"/)
    {
        $tcid_beg = ($1 << 24) | ($2 << 16) | ($3 << 8) | ($4 << 0);
        $tcid_end = ($1 << 24) | ($2 << 16) | ($3 << 8) | ($4 << 0);
    }

    if($line =~ /maski=\"(\S+)\"/)
    {
        $maski = $1;
    }

    if($line =~ /maske=\"(\S+)\"/)
    {
        $maske = $1;
    }

    if($line =~ /srvipaddr=\"(\S+)\"/)
    {
        $srvipaddr = $1;
    }
    elsif($line =~ /ipaddr=\"(\S+)\"/)
    {
        $srvipaddr = $1;
    }
    elsif($line =~ /ipv4=\"(\S+)\"/)
    {
        $srvipaddr = $1;
    }
    elsif($line =~ /ip=\"(\S+)\"/)
    {
        $srvipaddr = $1;
    }

    if($line =~ /srvport=\"(\d+)-(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $2;
    }
    elsif($line =~ /srvport=\"(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $1;
    }
    elsif($line =~ /sport=\"(\d+)-(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $2;
    }
    elsif($line =~ /sport=\"(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $1;
    }
    elsif($line =~ /port=\"(\d+)-(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $2;
    }
    elsif($line =~ /port=\"(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $1;
    }
    elsif($line =~ /bgn=\"(\d+)-(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $2;
    }
    elsif($line =~ /bgn=\"(\d+)\"/)
    {
        $srvport_beg = $1;
        $srvport_end = $1;
    }

    if($line =~ /csrvport=\"(\d+)-(\d+)\"/)
    {
        $csrvport_beg = $1;
        $csrvport_end = $2;
    }
    elsif($line =~ /csrvport=\"(\d+)\"/)
    {
        $csrvport_beg = $1;
        $csrvport_end = $1;
    }
    elsif($line =~ /cport=\"(\d+)-(\d+)\"/)
    {
        $csrvport_beg = $1;
        $csrvport_end = $2;
    }
    elsif($line =~ /cport=\"(\d+)\"/)
    {
        $csrvport_beg = $1;
        $csrvport_end = $1;
    }
    elsif($line =~ /rest=\"(\d+)-(\d+)\"/)
    {
        $csrvport_beg = $1;
        $csrvport_end = $2;
    }
    elsif($line =~ /rest=\"(\d+)\"/)
    {
        $csrvport_beg = $1;
        $csrvport_end = $1;
    }

    if($line =~ /cluster=\"(\S+)\"/)
    {
        @cluster_segs = split(/,/, $1);

        foreach $cluster_seg (@cluster_segs)
        {
            @cluster_seg_ids = split(/-/, $cluster_seg);
            $cluster_seg_ids_num = scalar(@cluster_seg_ids);

            next if(0 == $cluster_seg_ids_num);
            if(1 == $cluster_seg_ids_num)
            {
                $cluster_beg = $cluster_seg_ids[0];
                $cluster_end = $cluster_seg_ids[0];
            }
            else
            {
                $cluster_beg = $cluster_seg_ids[0];
                $cluster_end = $cluster_seg_ids[$cluster_seg_ids_num - 1];
            }

            for($cluster_id = $cluster_beg; $cluster_id <= $cluster_end; $cluster_id ++)
            {
                push(@cluster_ids, $cluster_id);
            }
        }

        $cluster = join(",", @cluster_ids);
    }

    if(defined($tcid_beg)     && defined($tcid_end)
    && defined($srvport_beg)  && defined($srvport_beg)
    && defined($csrvport_beg) && defined($csrvport_beg))
    {
        for($tcid = $tcid_beg, $srvport = $srvport_beg, $csrvport = $csrvport_beg;
           $tcid <= $tcid_end && $srvport <= $srvport_end && $csrvport <= $csrvport_end;
           $tcid ++, $srvport ++, $csrvport ++)
        {
            $tasks_config = {};

            $$tasks_config{"tcid"}      = sprintf("%d.%d.%d.%d",
                                                  ($tcid >> 24) & 0xFF,
                                                  ($tcid >> 16) & 0xFF,
                                                  ($tcid >>  8) & 0xFF,
                                                  ($tcid >>  0) & 0xFF);
            $$tasks_config{"maski"}     = $maski;
            $$tasks_config{"maske"}     = $maske;
            $$tasks_config{"srvipaddr"} = $srvipaddr;
            $$tasks_config{"srvport"}   = $srvport;
            $$tasks_config{"csrvport"}  = $csrvport;
            $$tasks_config{"cluster"}   = $cluster;

            push(@$task_config, $tasks_config);
        }
    }
}

########################################################################################################################
# task_config_parse($config_xml, %task_config)
########################################################################################################################
sub task_config_parse
{
    my $config_xml;
    my $task_config;

    my $tasks_config;

    my $line;

    ($config_xml, $task_config) = @_;

    while( <$config_xml> )
    {
        chomp($line = $_);

        if( $line =~ /<!--.*-->/ )
        {
            $line =~ s/<!--.*-->//g;
            next if($line eq "");
        }

        if( $line =~ /<!--/ )
        {
            $line = &skip_comments($config_xml);
            next if($line eq "");
        }

        last if($line =~ /<\/taskConfig>/);

        if($line =~ /<tasks\s+(.*)\/>/)
        {
            &tasks_config_parse($1, $task_config);
        }
    }
}

########################################################################################################################
# sys_config_parse($config_xml, %sys_config)
########################################################################################################################
sub sys_config_parse
{
    my $config_xml;
    my $sys_config;

    my $line;

    ($config_xml, $sys_config) = @_;

    while( <$config_xml> )
    {
        chomp($line = $_);

        if( $line =~ /<!--.*-->/ )
        {
            $line =~ s/<!--.*-->//g;
            next if($line eq "");
        }

        if( $line =~ /<!--/ )
        {
            $line = &skip_comments($config_xml);
            next if($line eq "");
        }

        last if($line =~ /<\/sysConfig>/);

        if($line =~ /<taskConfig>/)
        {
            $$sys_config{"taskConfig"} = [];
            &task_config_parse($config_xml, $$sys_config{"taskConfig"});
            next;
        }

        if($line =~ /<clusters>/)
        {
            # ignore
            next;
        }

        if($line =~ /<parasConfig>/)
        {
            # ignore
            next;
        }
    }
}

########################################################################################################################
# sys_config_xml_parse($config_xml, %sys_config)
########################################################################################################################
sub sys_config_xml_parse
{
    my $config_xml;
    my $sys_config;

    my $line;

    ($config_xml, $sys_config) = @_;

    open(SYS_CONFIG_XML, "< $config_xml") || die("cannot open ne list file $config_xml\n");

    while( <SYS_CONFIG_XML> )
    {
        chomp($line = $_);

        if( $line =~ /<!--.*-->/ )
        {
            $line =~ s/<!--.*-->//g;
            next if($line eq "");
        }

        if( $line =~ /<!--/ )
        {
            $line = &skip_comments(\*SYS_CONFIG_XML);
            next if($line eq "");
        }

        if($line =~ /<sysConfig>/)
        {
            &sys_config_parse(\*SYS_CONFIG_XML, $sys_config);
            next;
        }
    }

    close(SYS_CONFIG_XML);
}


################################################################################################################
# check_config(%config, $usage)
################################################################################################################
sub check_config
{
    my $config;
    my $usage;

    my $str;
    my @keys;
    my $key;

    my $invalid_flag;

    ($config, $usage) = @_;

    $str = $usage;
    $str =~ s/=<.*?>//g;

    @keys = split(/\s+/, $str);
    shift(@keys);

    $invalid_flag = 0;
    foreach $key (@keys)
    {
        next if(  $key =~ /^\[.*\]$/);

        if( ! defined($$config{ $key } ) )
        {
            &com_err("error: absent parameter of '$key'\n");
            $invalid_flag = 1;
        }
    }

    &com_die("err_args", "absent parameter(s)\nusage = $usage\n") if ( 0 ne $invalid_flag  );
}

################################################################################################################
# print_config(%config)
################################################################################################################
sub print_config
{
    my $config;

    my $key;
    my $value;

    ($config) = @_;

    while ( ($key, $value) = each (%$config) )
    {
        &com_dbg(sprintf("%-16s: %s\n", $key, $value));
    }
}

################################################################################################################
# fetch_config(%config, @argv)
################################################################################################################
sub fetch_config
{
    my $config;
    my @argv;

    my $arg_num;
    my $arg_idx;

    ($config, @argv) = @_;

    $arg_num = scalar(@argv);
    for($arg_idx = 0; $arg_idx < $arg_num; $arg_idx ++ )
    {
        if($argv[ $arg_idx ] =~ /(.*?)=(.*)/)
        {
            $$config{ $1 }  = $2;
            next;
        }
    }
}

################################################################################################################
# open_fp_autoflush(FILEHANDLE)
################################################################################################################
sub open_fp_autoflush
{
    my $fp;

    ($fp) = @_;

    $g_autoflush_flag = $|;
    $|                = 1;
    select($fp);
}

################################################################################################################
# restore_fp_autoflush(FILEHANDLE)
################################################################################################################
sub restore_fp_autoflush
{
    my $fp;

    ($fp) = @_;

    $| = $g_autoflush_flag;
    select($fp);
}

########################################################################################################################
# com_die($err_desc, @err_info)
########################################################################################################################
sub com_die
{
    my $err_desc;
    my @err_info;

    my $err_code;

    ($err_desc, @err_info) = @_;

    if($err_desc =~ /^\d+$/)
    {
        $err_code = $err_desc;
    }
    else
    {
        $err_code = defined($g_err_code{ $err_desc }) ? $g_err_code{ $err_desc } : $g_err_code{"err_undef"};
    }

    &com_err("err_code : $err_code\n") if ( 0 != $err_code );
    &com_err(join("", @err_info,"\n"));

    exit $err_code;
}

########################################################################################################################
# com_err($err_info)
########################################################################################################################
sub com_err
{
    my $err_info;

    my $date;

    ($err_info) = @_;

    chomp($date = `date '+%m/%d/20%y %H:%M:%S'`);
    printf STDERR ("[%s] %s", $date, $err_info) if defined($err_info);
}

########################################################################################################################
# com_dbg($info)
########################################################################################################################
sub com_dbg
{
    my $info;

    my $date;

    ($info) = @_;

    chomp($date = `date '+%m/%d/20%y %H:%M:%S'`);
    printf STDOUT ("[%s] %s", $date, $info) if defined($info);
}

