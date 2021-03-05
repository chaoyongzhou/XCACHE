#! /usr/bin/perl -w

########################################################################################################################
# description:  download file from server
# version    :  v1.2
# creator    :  chaoyong zhou
#
# History:
#    1. 02/23/2021: v1.0, delivered
#    2. 03/03/2021: v1.1, support sync directory
#    3. 03/05/2021: v1.2, support direct domain access
########################################################################################################################

use strict;

use LWP::UserAgent;
use Digest::MD5 qw(md5 md5_hex);
use File::Basename;

my $g_src_host;
my $g_src_ip;
my $g_timeout_nsec;
my $g_sleep_nsec    = 10;# default sleep 10s
my $g_step_nbytes;
my $g_log_level     = 1; # default log level

my $g_ua_agent = "Mozilla/8.0";

my $g_autoflush_flag;
my $g_usage =
    "$0 [syncfiles=<num>] des=<local file> src=<remote file> [ip=<server server ip[:port]>] [host=<hostname>] [sleep=<seconds>] [timeout=<seconds>] [step=<nbytes>] [loglevel=<1..9>] [verbose=on|off]";
my $verbose;

my $paras_config = {};

&fetch_config($paras_config, @ARGV);
&check_config($paras_config, $g_usage);

$verbose = $$paras_config{"verbose"}   if ( defined($$paras_config{"verbose"}) );
if( defined($verbose) && $verbose =~/on/i )
{
    &print_config($paras_config);
}

$g_src_host     = $$paras_config{"host"}        || "www.download.com";# default server domain
$g_src_ip       = $$paras_config{"ip"};
$g_timeout_nsec = $$paras_config{"timeout"}     || 30;              # default timeout in seconds
$g_sleep_nsec   = $$paras_config{"sleep"}       || 10;              # default sleep in seconds
$g_step_nbytes  = $$paras_config{"step"}        || 2 << 20;         # default segment size in bytes

if(defined($$paras_config{"loglevel"}))
{
    $g_log_level = $$paras_config{"loglevel"}; # loglevel range [0..9]
}

&open_fp_autoflush(\*STDOUT);

if(defined($$paras_config{"syncfiles"}) && 0 < $$paras_config{"syncfiles"})
{
    &sync_dir_entrance($$paras_config{"des"}, $$paras_config{"src"}, $$paras_config{"syncfiles"});

}
else
{
    &download_file_entrance($$paras_config{"des"}, $$paras_config{"src"});
}

&restore_fp_autoflush(\*STDOUT);

################################################################################################################
# $status = sync_dir_entrance($local_dir_name, $remote_dir_name, $sync_file_num)
################################################################################################################
sub sync_dir_entrance
{
    my $status;

    my $local_dir_name;
    my $remote_dir_name;
    my $sync_file_num;

    my $local_file_name;
    my $remote_file_name;

    my $sync_file_complete_num;

    ($local_dir_name, $remote_dir_name, $sync_file_num) = @_;

    # check src file name validity
    if(defined($remote_dir_name))
    {
        if($remote_dir_name !~ /^\//)
        {
            $remote_dir_name = "/".$remote_dir_name
        }

        $status = &check_dir_name_validity($remote_dir_name);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:download_file_entrance: invalid remote dir name '%s'\n",
                             $remote_dir_name));
            return 1; # fail
        }
    }

    # check des file name validity
    if(defined($local_dir_name))
    {
        $status = &check_dir_name_validity($local_dir_name);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:download_file_entrance: invalid local dir name '%s'\n",
                             $local_dir_name));
            return 1; # fail
        }
    }


    if(! -d $local_dir_name)
    {
        if(0 != system(sprintf("mkdir %s", $local_dir_name)))
        {
            &echo(0, sprintf("error:sync_dir_entrance: mkdir local dir '%s' failed\n",
                             $local_dir_name));
            return 1; # fail
        }
        &echo(2, sprintf("[DEBUG] sync_dir_entrance: mkdir local dir '%s' done\n",
                         $local_dir_name));
    }
    else
    {
        &echo(2, sprintf("[DEBUG] sync_dir_entrance: local dir '%s' exists\n",
                         $local_dir_name));
    }

    $sync_file_complete_num = 0;
    while($sync_file_complete_num < $sync_file_num)
    {
        my $local_basedir_name;

        ($status, $remote_file_name) = &finger_remote_dir_do($remote_dir_name);
        if(200 != $status)
        {
            &echo(0, sprintf("error:sync_dir_entrance: finger remote dir '%s' failed\n",
                             $remote_dir_name));
            return 1; # fail
        }

        if(! defined($remote_file_name))
        {
            &echo(1, sprintf("[DEBUG] sync_dir_entrance: no remote file => sleep %d seconds\n",
                             $g_sleep_nsec));
            sleep($g_sleep_nsec);
            next;
        }

        &echo(2, sprintf("[DEBUG] sync_dir_entrance: finger remote dir '%s' => '%s'\n",
                         $remote_dir_name, $remote_file_name));

        $local_file_name = sprintf("%s%s", $local_dir_name, $remote_file_name);

        $local_basedir_name = dirname($local_file_name);
        if(! -d $local_basedir_name)
        {
            if(!mkdir($local_basedir_name))
            {
                &echo(0, sprintf("error:sync_dir_entrance: make local basedir '%s' failed\n",
                                 $local_basedir_name));
                return 1; # fail
            }
            &echo(2, sprintf("[DEBUG] sync_dir_entrance: make local basedir '%s' done\n",
                             $local_basedir_name));
        }
        else
        {
            &echo(2, sprintf("[DEBUG] sync_dir_entrance: local basedir '%s' exists\n",
                             $local_basedir_name));
        }

        $status = &download_file_entrance($local_file_name, $remote_file_name);
        if(0 != $status)
        {
            &echo(0, sprintf("error:sync_dir_entrance: download '%s' -> '%s' failed\n",
                             $remote_file_name, $local_file_name));
            return 1; # fail
        }

        &echo(2, sprintf("[DEBUG] sync_dir_entrance: download '%s' -> '%s' done\n",
                         $remote_file_name, $local_file_name));

        $status = &backup_remote_file_do($remote_file_name);
        if(200 != $status)
        {
            &echo(0, sprintf("error:sync_dir_entrance: backup '%s' failed\n",
                             $remote_file_name));
            return 1; # fail
        }

        $sync_file_complete_num ++;

        &echo(2, sprintf("[DEBUG] sync_dir_entrance: backup '%s' done\n",
                         $remote_file_name));

        &echo(1, sprintf("[DEBUG] sync_dir_entrance: complete %d/%d, %.2f%%\n",
                         $sync_file_complete_num, $sync_file_num,
                         100.0 * ($sync_file_complete_num + 0.0) / ($sync_file_num + 0.0)));
    }

    return 0; # succ
}

################################################################################################################
# $status = download_file_entrance($local_file_name, $remote_file_name)
################################################################################################################
sub download_file_entrance
{
    my $status;

    my $local_file_name;
    my $remote_file_name;


    ($local_file_name, $remote_file_name) = @_;

    # check src file name validity
    if(defined($remote_file_name))
    {
        if($remote_file_name !~ /^\//)
        {
            $remote_file_name = "/".$remote_file_name
        }

        $status = &check_file_name_validity($remote_file_name);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:download_file_entrance: invalid remote file name '%s'\n",
                             $remote_file_name));
            return 1; # fail
        }
    }

    # check des file name validity
    if(defined($local_file_name))
    {
        $status = &check_file_name_validity($local_file_name);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:download_file_entrance: invalid local file name '%s'\n",
                             $local_file_name));
            return 1; # fail
        }
    }

    $status = &download_file($local_file_name, $remote_file_name);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:download_file_entrance: %s:%s:download '%s' -> '%s' failed\n",
                         &get_remote_host(), &get_remote_ip(), $remote_file_name,
                         $local_file_name));
        return 1; # fail
    }

    &echo(1, sprintf("[DEBUG] download_file_entrance: download %s:%s:'%s' -> '%s' succ\n",
                     &get_remote_host(), &get_remote_ip(), $remote_file_name,
                     $local_file_name));

    if( defined($verbose) && $verbose =~/on/i )
    {
        my $remote_file_size;
        my $remote_file_md5;

        my $local_file_size;
        my $local_file_md5;

        ($status, $remote_file_size) = &size_remote_file_do($remote_file_name);
        &echo(0, sprintf("[DEBUG] download_file_entrance: remote  file size %d\n", $remote_file_size));

        ($status, $local_file_size) = &size_local_file_do($local_file_name);
        &echo(0, sprintf("[DEBUG] download_file_entrance: local file size %d\n", $local_file_size));

        ($status, $remote_file_md5) = &md5_remote_file_do($remote_file_name,
                                                          0, $remote_file_size, $remote_file_size);
        &echo(0, sprintf("[DEBUG] download_file_entrance: remote  file md5 %s\n", $remote_file_md5));

        ($status, $local_file_md5)  = &md5_local_file_do($local_file_name,
                                                         0, $local_file_size, $local_file_size);
        &echo(0, sprintf("[DEBUG] download_file_entrance: local file md5 %s\n", $local_file_md5));
    }

    return 0; # succ
}

################################################################################################################
# $bool = check_file_name_validity($file_name)
################################################################################################################
sub check_file_name_validity
{
    my $file_name;
    my $file_name_segs;
    my $file_name_seg;

    ($file_name) = @_;

    $file_name_segs = [];
    @$file_name_segs = split('/', $file_name);

    foreach $file_name_seg (@$file_name_segs)
    {
        if($file_name_seg eq "..")
        {
            &echo(0, sprintf("error:check_file_name_validity: file name '%s' contains '..'\n",
                             $file_name));
            return "false";
        }

        # posix compatiblity
        if(255 < length($file_name_seg))
        {
            &echo(0, sprintf("error:check_file_name_validity: file name '%s' seg len > 255\n",
                             $file_name));
            return "false";
        }
    }
    return "true";
}

################################################################################################################
# $bool = check_dir_name_validity($dir_name)
################################################################################################################
sub check_dir_name_validity
{
    my $dir_name;
    my $dir_name_segs;
    my $dir_name_seg;

    ($dir_name) = @_;

    $dir_name_segs = [];
    @$dir_name_segs = split('/', $dir_name);

    foreach $dir_name_seg (@$dir_name_segs)
    {
        if($dir_name_seg eq "..")
        {
            &echo(0, sprintf("error:check_dir_name_validity: file name '%s' contains '..'\n",
                             $dir_name));
            return "false";
        }

        # posix compatiblity
        if(255 < length($dir_name_seg))
        {
            &echo(0, sprintf("error:check_dir_name_validity: file name '%s' seg len > 255\n",
                             $dir_name));
            return "false";
        }
    }
    return "true";
}

################################################################################################################
# $status = backup_remote_file_do($remote_file_name)
################################################################################################################
sub backup_remote_file_do
{
    my $remote_file_name;

    my $ua;
    my $url;
    my $res;

    ($remote_file_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("backup", $remote_file_name);

    $res = $ua->get($url,
                'Host' => &get_remote_host());

    &echo(9, sprintf("[DEBUG] backup_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] backup_remote_file_do: headers: %s\n", $res->headers_as_string));


    return $res->code;
}

################################################################################################################
# ($status, $remote_file_name) = finger_remote_dir_do($remote_dir_name)
################################################################################################################
sub finger_remote_dir_do
{
    my $remote_dir_name;

    my $ua;
    my $url;
    my $res;
    my $k;

    ($remote_dir_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("finger", $remote_dir_name);

    $res = $ua->get($url,
                'Host' => &get_remote_host());

    &echo(9, sprintf("[DEBUG] finger_remote_dir_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] finger_remote_dir_do: headers: %s\n", $res->headers_as_string));

    $k = "X-File";
    &echo(8, sprintf("[DEBUG] finger_remote_dir_do: %s:%s\n", $k, $res->header($k) || "-"));

    return ($res->code, $res->header($k) || undef);
}

################################################################################################################
# ($status, $file_size) = size_remote_file_do($remote_file_name)
################################################################################################################
sub size_remote_file_do
{
    my $remote_file_name;

    my $ua;
    my $url;
    my $res;
    my $k;

    ($remote_file_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("size", $remote_file_name);

    $res = $ua->get($url,
                'Host' => &get_remote_host());

    &echo(9, sprintf("[DEBUG] size_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] size_remote_file_do: headers: %s\n", $res->headers_as_string));

    $k = "X-File-Size";
    &echo(8, sprintf("[DEBUG] size_remote_file_do: %s:%s\n", $k, $res->header($k) || "0"));

    return ($res->code, $res->header($k) || "0");
}

################################################################################################################
# ($status, $md5hex) = md5_remote_file_do($remote_file_name, $s_offset, $e_offset, $file_size)
################################################################################################################
sub md5_remote_file_do
{
    my $ua;
    my $url;
    my $content_range;
    my $res;
    my $k;

    my $remote_file_name;
    my $s_offset;
    my $e_offset;
    my $file_size;

    # [s_offset, e_offset) /  file_size
    ($remote_file_name, $s_offset, $e_offset, $file_size) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent);
    $ua->timeout($g_timeout_nsec);

    $e_offset = $e_offset - 1;

    $url = &make_url("md5", $remote_file_name);

    $content_range = sprintf("bytes %d-%d/%d", $s_offset, $e_offset, $file_size);

    $res = $ua->get($url,
                'Host'          => &get_remote_host(),
                'Content-Range' => $content_range);

    &echo(8, sprintf("[DEBUG] md5_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] md5_remote_file_do: headers: %s\n", $res->headers_as_string));

    $k = "X-MD5";
    &echo(8, sprintf("[DEBUG] md5_remote_file_do: %s:%s\n",$k, $res->header($k) || "-"));

    return ($res->code, $res->header($k) || "-");
}

################################################################################################################
# $status = del_remote_file_do($remote_file_name)
################################################################################################################
sub del_remote_file_do
{
    my $ua;
    my $url;
    my $res;

    my $remote_file_name;

    ($remote_file_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("delete", $remote_file_name);

    $res = $ua->get($url,
                'Host' => &get_remote_host());

    &echo(8, sprintf("[DEBUG] del_remote_file_do: status : %d\n", $res->code));

    return $res->code
}

################################################################################################################
# $status = download_remote_file_do($local_file_name, $remote_file_name, $s_offset, $e_offset, $file_size)
################################################################################################################
sub download_remote_file_do
{
    my $ua;
    my $url;
    my $content_range;
    my $res;

    my $local_file_name;
    my $remote_file_name;
    my $s_offset;
    my $e_offset;
    my $file_size;

    my $status;

    ($local_file_name, $remote_file_name, $s_offset, $e_offset, $file_size) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent);
    $ua->timeout($g_timeout_nsec);

    $e_offset = $e_offset - 1;

    $url = &make_url("download", $remote_file_name);

    $content_range = sprintf("bytes %d-%d/%d", $s_offset, $e_offset, $file_size);

    $res = $ua->get($url,
                'Content-Type'  => "text/html; charset=utf-8",
                'Host'          => &get_remote_host(),
                'Content-Range' => $content_range);

    &echo(8, sprintf("[DEBUG] download_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] download_remote_file_do: headers: %s\n", $res->headers_as_string));

    &echo(2, sprintf("[DEBUG] download_remote_file_do: %s, %d-%d/%d => %d\n",
                     $remote_file_name,
                     $s_offset, $e_offset, $file_size,
                     $res->code));

    if(200 != $res->code)
    {
        return "false";
    }

    # write to part file
    $e_offset = $e_offset + 1;

    $status = &dump_local_file_part_do($local_file_name, $s_offset, $e_offset, $file_size, $res->content());
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:download_remote_file_do: dump file '%s' %d-%d/%d failed",
                         $local_file_name, $s_offset, $e_offset, $file_size));
        return "false";
    }

    return "true";
}


################################################################################################################
# $bool = dump_local_file_part_do($local_file_name, $s_offset, $e_offset, $remote_file_size)
################################################################################################################
sub dump_local_file_part_do
{
    my $status;

    my $local_file_name;
    my $s_offset;
    my $e_offset;
    my $remote_file_size;

    my $fp;
    my $data;

    my $local_file_part_name;

    ($local_file_name, $s_offset, $e_offset, $remote_file_size, $data) = @_;

    $local_file_part_name = sprintf("%s.part_%d_%d_%d",
                                    $local_file_name, $s_offset, $e_offset, $remote_file_size);

    open($fp, ">", $local_file_part_name) || die(sprintf("error:dump_local_file_part_do: cannot open file %s",
                                                         $local_file_part_name));
    binmode($fp, ":bytes");

    $status = syswrite($fp, $data, $e_offset - $s_offset);
    if(! defined($status))
    {
        close($fp);

        &echo(0, sprintf("error:dump_local_file_part_do: write part file '%s' failed",
                         $local_file_part_name));
        return "false";
    }

    close($fp);

    return "true";
}

################################################################################################################
# $bool = override_local_file_part_do($local_file_name, $s_offset, $e_offset, $remote_file_size)
################################################################################################################
sub override_local_file_part_do
{
    my $status;

    my $local_file_name;
    my $s_offset;
    my $e_offset;
    my $remote_file_size;

    my $block_size;
    my $seek_blocks;
    my $dd_command;

    my $local_file_part_name;

    ($local_file_name, $s_offset, $e_offset, $remote_file_size) = @_;

    $local_file_part_name = sprintf("%s.part_%d_%d_%d",
                                    $local_file_name, $s_offset, $e_offset, $remote_file_size);

    # override: dd file part to specific position of des file
    $block_size  = 512;
    $seek_blocks = $s_offset / $block_size;
    if(0 != ($s_offset % $block_size))
    {
        die(sprintf("error:override_local_file_part_do: s_offset %d, block_size %d => not aligned\n",
                    $s_offset, $block_size));
    }

    $dd_command = sprintf("dd if=%s of=%s bs=%d seek=%d > /dev/null 2>&1",
                         $local_file_part_name, $local_file_name,
                         $block_size, $seek_blocks);

    $status = system($dd_command);
    if(0 != $status)
    {
        die(sprintf("error:override_local_file_part_do: cmd '%s'", $dd_command));
    }

    &echo(2, sprintf("[DEBUG] override_local_file_part_do: override '%s' %d-%d/%d done\n",
                     $local_file_name, $s_offset, $e_offset, $remote_file_size));

    return "true";
}

################################################################################################################
# $bool = del_local_file_part_do($local_file_name, $s_offset, $e_offset, $remote_file_size)
################################################################################################################
sub del_local_file_part_do
{
    my $local_file_name;
    my $s_offset;
    my $e_offset;
    my $remote_file_size;

    my $local_file_part_name;

    ($local_file_name, $s_offset, $e_offset, $remote_file_size) = @_;

    $local_file_part_name = sprintf("%s.part_%d_%d_%d",
                                    $local_file_name, $s_offset, $e_offset, $remote_file_size);

    unlink($local_file_part_name);
    return "true";
}


################################################################################################################
# $bool = merge_local_file_do($local_file_name, $s_offset, $e_offset, $remote_file_size)
################################################################################################################
sub merge_local_file_do
{
    my $status;

    my $local_file_name;
    my $s_offset;
    my $e_offset;

    my $s_offset_t;
    my $e_offset_t;

    my $src_offset_t;
    my $des_offset_t;

    my $local_file_size;
    my $remote_file_size;

    my $local_file_part_name;

    ($local_file_name, $s_offset, $e_offset, $remote_file_size) = @_;

    $s_offset_t = $s_offset;
    $e_offset_t = $e_offset;

    ($status, $local_file_size) = &size_local_file_do($local_file_name);
    if($status =~ /false/i)
    {
        $local_file_size = 0;
    }

    if($s_offset_t != $local_file_size)
    {
        &echo(0, sprintf("error:merge_local_file_do: local file size %d, range %d-%d is invalid\n",
                         $local_file_size, $s_offset_t, $e_offset_t));

        return "false";
    }

    $local_file_part_name = sprintf("%s.part_%d_%d_%d",
                                    $local_file_name, $s_offset, $e_offset, $remote_file_size);

    system(sprintf("cat %s >> %s", $local_file_part_name, $local_file_name));
    unlink($local_file_part_name);

    &echo(2, sprintf("[DEBUG] merge_local_file_do: append local file '%s' %d-%d done\n",
                     $local_file_name, $s_offset, $e_offset));

    return "true";
}

################################################################################################################
# $status = override_local_file_do($local_file_name, $remote_file_name,
#                                  $s_offset, $e_offset,
#                                  $local_file_size, $remote_file_size)
################################################################################################################
sub override_local_file_do
{
    my $ua;
    my $url;
    my $content_range;
    my $res;

    my $local_file_name;
    my $remote_file_name;
    my $s_offset;
    my $e_offset;
    my $local_file_size;
    my $remote_file_size;

    my $status;

    ($local_file_name, $remote_file_name, $s_offset, $e_offset, $local_file_size, $remote_file_size) = @_;

    if($s_offset >= $e_offset)
    {
        &echo(0, sprintf("error:override_local_file_do: invalid range %d-%d\n",
                         $s_offset, $e_offset));
        return "false";
    }

    if($e_offset > $remote_file_size)
    {
        &echo(0, sprintf("error:override_local_file_do: remote file size %d, invalid range %d-%d\n",
                         $remote_file_size, $s_offset, $e_offset));
        return "false";
    }

    if($e_offset > $local_file_size)
    {
        &echo(0, sprintf("error:override_local_file_do: local file size %d, invalid range %d-%d\n",
                         $local_file_size, $s_offset, $e_offset));
        return "false";
    }

    $ua = LWP::UserAgent->new;

    $ua->agent("Mozilla/8.0");
    $ua->timeout($g_timeout_nsec);

    $e_offset = $e_offset - 1;

    $url = &make_url("download", $remote_file_name);
    $content_range = sprintf("bytes %d-%d/%d", $s_offset, $e_offset, $remote_file_size);

    $res = $ua->get($url,
                'Content-Type'  => "text/html; charset=utf-8",
                'Host'          => &get_remote_host(),
                'Content-Range' => $content_range);

    &echo(8, sprintf("[DEBUG] override_local_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] override_local_file_do: headers: %s\n", $res->headers_as_string));

    &echo(2, sprintf("[DEBUG] override_local_file_do: %s, %d-%d/%d => %d\n",
                     $remote_file_name,
                     $s_offset, $e_offset, $remote_file_size,
                     $res->code));

    if(200 != $res->code)
    {
        &echo(0, sprintf("[DEBUG] override_local_file_do: %s, %d-%d/%d => %d\n",
                         $remote_file_name,
                         $s_offset, $e_offset, $remote_file_size,
                         $res->code));
        return "false";
    }

    # override

    $e_offset = $e_offset + 1;

    # dump file part
    $status = &dump_local_file_part_do($local_file_name,
                                        $s_offset, $e_offset, $remote_file_size,
                                        $res->content());
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:override_local_file_do: dump file part '%s' %d-%d/%d failed",
                         $local_file_name, $s_offset, $e_offset, $remote_file_size));
        return "false";
    }

    # override file part
    $status = &override_local_file_part_do($local_file_name, $s_offset, $e_offset, $remote_file_size);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:override_local_file_do: override file part '%s' %d-%d/%d failed",
                         $local_file_name, $s_offset, $e_offset, $remote_file_size));
        return "false";
    }

    # delete file part
    $status = &del_local_file_part_do($local_file_name, $s_offset, $e_offset, $remote_file_size);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:override_local_file_do: del file part '%s' %d-%d/%d failed",
                         $local_file_name, $s_offset, $e_offset, $remote_file_size));
        return "false";
    }

    return "true";
}

################################################################################################################
# ($status, $file_size) = size_local_file_do($local_file_name)
################################################################################################################
sub size_local_file_do
{
    my $local_file_name;

    ($local_file_name) = @_;

    if(-e $local_file_name)
    {
        my @file_stats = stat ($local_file_name);
        return ("true", $file_stats[7]);
    }

    return ("false", -1);
}

################################################################################################################
# ($bool, $md5hex) = md5_local_file_do($local_file_name, $s_offset, $e_offset, $file_size)
################################################################################################################
sub md5_local_file_do
{
    my $ctx;
    my $data;

    my $local_file_name;
    my $s_offset;
    my $e_offset;
    my $file_size;
    my $fp;

    my $len;
    my $ret;

    # [s_offset, e_offset) /  file_size
    ($local_file_name, $s_offset, $e_offset, $file_size) = @_;

    $ctx = Digest::MD5->new;

    open($fp, "<", $local_file_name) || die sprintf("cannot open file %s", $local_file_name);
    binmode($fp, ":bytes");

    seek($fp, $s_offset, 0) || die sprintf("seek file %s at offset %d failed", $local_file_name, $s_offset);

    while($s_offset < $file_size && $s_offset < $e_offset)
    {
        $len = $g_step_nbytes;
        if($s_offset + $len > $file_size)
        {
            $len = $file_size - $s_offset;
        }
        if($s_offset + $len > $e_offset)
        {
            $len = $e_offset - $s_offset;
        }

        $ret = read($fp, $data, $len);
        if(! defined($ret))
        {
            die sprintf("error:md5_local_file_do: read %d-%d/%d failed",
                        $s_offset, $s_offset + $len, $file_size);
        }

        last if(0 == $ret);

        $ctx->add($data);

        $s_offset = $s_offset + $len;
    }

    close($fp);

    return ("true", $ctx->hexdigest);
}

################################################################################################################
# md5_local_file_check($local_file_name, $remote_file_name)
################################################################################################################
sub md5_local_file_check
{
    my $ctx;
    my $data;

    my $s_offset;
    my $e_offset;
    my $file_size;
    my $fp;

    my $local_file_name;
    my $remote_file_name;

    my $len;
    my $ret;

    ($local_file_name, $remote_file_name) = @_;

    $ctx = Digest::MD5->new;

    ($ret, $file_size) = &size_local_file_do($local_file_name);
    $s_offset = 0;
    $e_offset = $file_size;

    &echo(0, sprintf("[DEBUG] md5_local_file_check: local file '%s', size %d\n",
                     $local_file_name, $file_size));

    while($s_offset < $file_size && $s_offset < $e_offset)
    {
        my $md5;

        $len = $g_step_nbytes;
        if($s_offset + $len > $file_size)
        {
            $len = $file_size - $s_offset;
        }
        if($s_offset + $len > $e_offset)
        {
            $len = $e_offset - $s_offset;
        }

        ($ret, $md5) = &md5_local_file_do($local_file_name, $s_offset, $e_offset, $file_size);
        &echo(0, sprintf("[DEBUG] md5_local_file_check: local file '%s', %d-%d/%d => md5 %s\n",
                         $local_file_name, $s_offset, $e_offset, $file_size, $md5));

        $s_offset = $s_offset + $len;
    }
    return;
}

################################################################################################################
# ($bool, $s_offset) = finger_start_seg_do($local_file_name, $remote_file_name,
#                                          $local_file_size, $remote_file_size)
################################################################################################################
sub finger_start_seg_do
{
    my $status;

    my $local_file_name;
    my $remote_file_name;

    my $remote_file_size;
    my $local_file_size;

    my $remote_file_md5;
    my $local_file_md5;

    my $s_offset;
    my $e_offset;

    ($local_file_name, $remote_file_name, $local_file_size, $remote_file_size) = @_;

    $s_offset = 0;
    while($s_offset < $remote_file_size && $s_offset < $local_file_size)
    {
        $e_offset = $s_offset + $g_step_nbytes;

        if($e_offset > $remote_file_size)
        {
            $e_offset = $remote_file_size;
        }

        if($e_offset > $local_file_size)
        {
            $e_offset = $local_file_size;
        }

        ($status, $remote_file_md5) = &md5_remote_file_do($remote_file_name,
                                                          $s_offset, $e_offset, $remote_file_size);
        if(200 != $status)
        {
            return ("false", $s_offset);
        }
        &echo(2, sprintf("[DEBUG] finger_start_seg_do: md5 remote file %s %d-%d/%d is %s\n",
                        $remote_file_name, $s_offset, $e_offset, $remote_file_size, $remote_file_md5));


        ($status, $local_file_md5) = &md5_local_file_do($local_file_name,
                                                        $s_offset, $e_offset, $local_file_size);
        if($status =~ /false/i)
        {
            return ("false", $s_offset);
        }
        &echo(2, sprintf("[DEBUG] finger_start_seg_do: md5 local file %s %d-%d/%d is %s\n",
                        $local_file_name, $s_offset, $e_offset, $local_file_size, $local_file_md5));

        if($remote_file_md5 ne $local_file_md5)
        {
            &echo(2, sprintf("[DEBUG] finger_start_seg_do: %d-%d mismatched\n", $s_offset, $e_offset));
            return ("true", $s_offset);
        }

        &echo(2, sprintf("[DEBUG] finger_start_seg_do: %d-%d matched\n", $s_offset, $e_offset));

        $s_offset = $e_offset;
    }

    return ("true", $s_offset);
}

################################################################################################################
# ($bool, $s_offset) = append_file($local_file_name, $remote_file_name,
#                                  $s_offset, $e_offset, $remote_file_size)
################################################################################################################
sub append_file
{
    my $status;

    my $local_file_name;
    my $remote_file_name;
    my $s_offset;
    my $e_offset;

    my $s_offset_t;
    my $e_offset_t;

    my $local_file_size;
    my $remote_file_size;

    ($local_file_name, $remote_file_name, $s_offset, $e_offset, $remote_file_size) = @_;

    $s_offset_t = $s_offset;

    ($status, $local_file_size) = &size_local_file_do($local_file_name);
    if($status =~ /false/i)
    {
        $local_file_size = 0;
    }

    if($s_offset_t >= $e_offset)
    {
        &echo(0, sprintf("error:append_file: local file %s, invalid range %d-%d\n",
                         $local_file_name, $s_offset, $e_offset));
        return ("false", $s_offset_t);
    }

    if($s_offset_t != $local_file_size)
    {
        &echo(0, sprintf("error:append_file: local file %s, size %d, invalid range %d-%d\n",
                         $local_file_name, $local_file_size, $s_offset, $e_offset));
        return ("false", $s_offset_t);
    }

    while($s_offset_t < $e_offset && $s_offset_t < $remote_file_size)
    {
        $e_offset_t = $s_offset_t + $g_step_nbytes;
        if($e_offset_t > $e_offset)
        {
            $e_offset_t = $e_offset;
        }
        if($e_offset_t > $remote_file_size)
        {
            $e_offset_t = $remote_file_size;
        }

        $status = &download_remote_file_do($local_file_name, $remote_file_name,
                                           $s_offset_t, $e_offset_t, $remote_file_size);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:append_file: download %s %d-%d/%d failed, status %d\n",
                             $remote_file_name, $s_offset_t, $e_offset_t,
                             $remote_file_size, $status));

            return ("false", $s_offset_t);
        }
        &echo(9, sprintf("[DEBUG] append_file: download %s %d-%d/%d done\n",
                         $remote_file_name, $s_offset_t, $e_offset_t, $remote_file_size));

        $status = &merge_local_file_do($local_file_name, $s_offset_t, $e_offset_t, $remote_file_size);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:append_file: merge %s %d-%d/%d failed\n",
                             $local_file_name,
                             $s_offset_t, $e_offset_t, $remote_file_size));
            return ("false", $s_offset_t);
        }
        &echo(9, sprintf("[DEBUG] append_file: merge %s %d-%d/%d done\n",
                         $local_file_name, $s_offset_t, $e_offset_t, $remote_file_size));

        &echo(1, sprintf("[DEBUG] append_file: append %s, %d-%d/%d => complete %.2f%%\n",
                         $local_file_name,
                         $s_offset_t, $e_offset_t, $remote_file_size,
                         100.0 * ($e_offset_t + 0.0) / ($remote_file_size + 0.0)));

        $s_offset_t = $e_offset_t;
    }

    return ("true", $s_offset_t);
}

################################################################################################################
# ($bool, $s_offset) = override_file($local_file_name, $remote_file_name,
#                                    $s_offset, $e_offset, $local_file_size, $remote_file_size)
################################################################################################################
sub override_file
{
    my $status;

    my $local_file_name;
    my $remote_file_name;
    my $remote_file_size;
    my $local_file_size;

    my $s_offset;
    my $e_offset;

    my $s_offset_t;
    my $e_offset_t;


    ($local_file_name, $remote_file_name, $s_offset, $e_offset, $local_file_size, $remote_file_size) = @_;

    $s_offset_t = $s_offset;
    while($s_offset_t < $e_offset
    && $s_offset_t < $remote_file_size
    && $s_offset_t < $local_file_size)
    {
        $e_offset_t = $s_offset_t + $g_step_nbytes;
        if($e_offset_t > $e_offset)
        {
            $e_offset_t = $e_offset;
        }
        if($e_offset_t > $remote_file_size)
        {
            $e_offset_t = $remote_file_size;
        }
        if($e_offset_t > $local_file_size)
        {
            $e_offset_t = $local_file_size;
        }

        $status = &override_local_file_do($local_file_name, $remote_file_name,
                                          $s_offset_t, $e_offset_t,
                                          $local_file_size, $remote_file_size);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:override_file: override %s %d-%d/%d failed\n",
                             $local_file_name, $s_offset_t, $e_offset_t,
                             $remote_file_size));

            return ("false", $s_offset_t);
        }
        &echo(9, sprintf("[DEBUG] override_file: override %s %d-%d/%d done\n",
                      $local_file_name, $s_offset_t, $e_offset_t, $remote_file_size));

        &echo(1, sprintf("[DEBUG] override_file: override %s, %d-%d/%d => complete %.2f%%\n",
                         $local_file_name,
                         $s_offset_t, $e_offset_t, $remote_file_size,
                         100.0 * ($e_offset_t + 0.0) / ($remote_file_size + 0.0)));

        $s_offset_t = $e_offset_t;
    }

    return ("true", $s_offset_t);
}

################################################################################################################
# $bool = download_file($local_file_name, $remote_file_name)
################################################################################################################
sub download_file
{
    my $status;

    my $local_file_name;
    my $remote_file_name;

    my $remote_file_size;
    my $remote_file_md5;

    my $local_file_size;
    my $local_file_md5;

    my $s_offset;
    my $e_offset;

    ($local_file_name, $remote_file_name) = @_;

    ($status, $remote_file_size) = &size_remote_file_do($remote_file_name);
    if(200 != $status)
    {
        &echo(0, sprintf("error:download_file: not found %s\n", $remote_file_name));
        return "false";
    }

    ($status, $local_file_size) = &size_local_file_do($local_file_name);

    # local file not exist
    if($status =~ /false/i)
    {
        &echo(9, sprintf("[DEBUG] download_file: remote file size: %d\n",
                         $remote_file_size));

        $s_offset = 0;
    }

    # local file exist
    else
    {
        &echo(9, sprintf("[DEBUG] download_file: remote file size: %d, local file size: %d\n",
                         $remote_file_size, $local_file_size));

        if(0 == $remote_file_size)
        {
            if(0 < $local_file_size)
            {
                truncate($local_file_name, 0) || die(sprintf("error:download_file: truncate %s failed\n",
                                                             $local_file_name));

                &echo(1, sprintf("[DEBUG] download_file: empty local file %s done\n",
                                 $local_file_name));
            }
            &echo(1, sprintf("[DEBUG] download_file: empty file => succ\n"));
            return "true";
        }

        if($remote_file_size < $local_file_size)
        {
            unlink($local_file_name);

            $s_offset = 0;

            &echo(1, sprintf("[DEBUG] download_file: remote file size %d < local file size %ld, del local file %s done\n",
                              $remote_file_size, $local_file_size, $local_file_name));
        }
        elsif(0 == $local_file_size)
        {
            $s_offset = 0;
        }
        else # $remote_file_size >= $local_file_size && $local_file_size > 0
        {
            ($status, $remote_file_md5) = &md5_remote_file_do($remote_file_name,
                                                        0, $local_file_size, $remote_file_size);
            if(200 != $status)
            {
                &echo(0, sprintf("error:download_file: md5 remote file %s, %d-%d/%d failed\n",
                                 $remote_file_name, 0, $local_file_size, $remote_file_size));
                return "false";
            }
            &echo(1, sprintf("[DEBUG] download_file: md5 %d-%d/%d => %s, remote  file %s\n",
                             0, $local_file_size, $remote_file_size,
                             $remote_file_md5,
                             $remote_file_name));

            ($status, $local_file_md5) = &md5_local_file_do($local_file_name,
                                                    0, $local_file_size, $local_file_size);
            if($status =~ /false/i)
            {
                &echo(0, sprintf("error:download_file: md5 local file %s failed\n", $local_file_name));
                return "false";
            }
            &echo(1, sprintf("[DEBUG] download_file: md5 %d-%d/%d => %s, local file %s\n",
                             0, $local_file_size, $local_file_size,
                             $local_file_md5,
                             $local_file_name));

            if($remote_file_md5 eq $local_file_md5)
            {
                if($remote_file_size == $local_file_size)
                {
                    &echo(2, sprintf("[DEBUG] download_file: same file => succ\n"));
                    return "true";
                }

                $s_offset = 0;
                $e_offset = $local_file_size;

                &echo(1, sprintf("[DEBUG] download_file: skip %s, %d-%d/%d => complete %.2f%%\n",
                                 $local_file_name,
                                 $s_offset, $e_offset, $remote_file_size,
                                 100.0 * ($e_offset + 0.0) / ($remote_file_size + 0.0)));

                $s_offset = $local_file_size;
            }
            else
            {
                ($status, $s_offset) = &finger_start_seg_do($local_file_name, $remote_file_name,
                                                            $local_file_size, $remote_file_size);
                if($status =~ /false/i)
                {
                    &echo(0, sprintf("error:download_file: file %s, finger start seg failed, s_offset = %d\n",
                                    $local_file_name, $s_offset));
                    return "false";
                }
                &echo(1, sprintf("[DEBUG] download_file: file %s, finger start seg done, s_offset = %d\n",
                                 $local_file_name, $s_offset));

                ($status, $s_offset) = &override_file($local_file_name, $remote_file_name,
                                                      $s_offset, $local_file_size,
                                                      $local_file_size, $remote_file_size);
                if($status =~ /false/i)
                {
                    &echo(0, sprintf("error:download_file: file %s, override failed, s_offset = %d\n",
                                     $local_file_name, $s_offset));
                    return "false";
                }
                &echo(1, sprintf("[DEBUG] download_file: file %s, override done, s_offset = %d\n",
                                 $local_file_name, $s_offset));
            }
        }
    }

    # optimize: alignment
    if(0 != ($s_offset % $g_step_nbytes))
    {
        $e_offset = $s_offset + $g_step_nbytes - ($s_offset % $g_step_nbytes);
        if($e_offset > $remote_file_size)
        {
            $e_offset = $remote_file_size;
        }

        ($status, $s_offset) = &append_file($local_file_name, $remote_file_name,
                                            $s_offset, $e_offset, $remote_file_size);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:download_file: file %s, append seg failed, s_offset = %d\n",
                             $remote_file_name, $s_offset));
            return "false";
        }
    }

    ($status, $s_offset) = &append_file($local_file_name, $remote_file_name,
                                        $s_offset, $remote_file_size, $remote_file_size);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:download_file: file %s, append failed, s_offset = %d\n",
                         $remote_file_name, $s_offset));
        return "false";
    }

    &echo(1, sprintf("[DEBUG] download_file: download %s done\n", $local_file_name));
    return "true";
}

################################################################################################################
# $url = make_url($op, $remote_path)
################################################################################################################
sub make_url
{
    my $op;
    my $remote_path;

    ($op, $remote_path) = @_;

    return sprintf("http://%s/%s%s", &get_remote_ip() || &get_remote_host(), $op, $remote_path);
}

################################################################################################################
# $ip = get_remote_ip()
################################################################################################################
sub get_remote_ip
{
    return $g_src_ip || &get_remote_host();
}

################################################################################################################
# $host = get_remote_host()
################################################################################################################
sub get_remote_host
{
    return $g_src_host;
}

################################################################################################################
# echo($loglevel, $msg)
################################################################################################################
sub echo
{
    my $log_level;
    my $msg;

    my $date;

    ($log_level, $msg) = @_;
    if($log_level <= $g_log_level)
    {
        chomp($date = `date '+%m/%d/20%y %H:%M:%S'`);

        printf STDOUT ("[%s] %s", $date, $msg) if defined($msg);
    }
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
        next if(  $key =~ /^\[.*\]$/ );

        if( ! defined( $$config{ $key } ) )
        {
            &echo(0, "error: absent parameter of $key\n");
            $invalid_flag = 1;
        }
    }

    &echo(0, "absent parameter(s)\nusage = $usage\n") if ( 0 ne $invalid_flag  );
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
        &echo(0, sprintf("%-16s: %s\n", $key, $value));
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
    for( $arg_idx = 0; $arg_idx < $arg_num; $arg_idx ++ )
    {
        if( $argv[ $arg_idx ] =~ /(.*?)=(.*)/ )
        {
            $$config{ $1 }  = $2;
            next;
        }
    }
}

################################################################################################################
# finger_config(%config, $k, $default_v)
################################################################################################################
sub finger_config
{
    my $config;
    my $k;
    my $v;

    my $arg_num;
    my $arg_idx;

    ($config, $k, $v) = @_;

    if(defined($$config{ $k }))
    {
        return $$config{ $k };
    }

    return $v;
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

