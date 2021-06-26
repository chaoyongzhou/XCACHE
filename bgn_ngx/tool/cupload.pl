#! /usr/bin/perl -w

########################################################################################################################
# description:  upload file to server
# version    :  v1.8
# creator    :  chaoyong zhou
#
# History:
#    1. 02/23/2021: v1.0, delivered
#    2. 02/26/2021: v1.1, support merge file parts
#    3. 03/03/2021: v1.2, support sync directory
#    4. 03/05/2021: v1.3, support direct domain access
#    5. 03/11/2021: v1.4, support acl based on token and time
#    6. 03/31/2021: v1.5, support complete interface which push file to backend storage
#    7. 06/01/2021: v1.6, support specific acl token of specific bucket
#    8. 06/01/2021: v1.7, fix merge remote file handler which not need carry on data
#    9. 06/25/2021: v1.8, set Range in http request header but not Content-Range
########################################################################################################################

use strict;

use LWP::UserAgent;
use Digest::MD5 qw(md5 md5_hex);

my $g_des_host;
my $g_des_ip;
my $g_timeout_nsec;
my $g_step_nbytes;
my $g_log_level     = 1; # default log level
my $g_acl_token;
my $g_expired_nsec  = 15;
my $g_ua_agent      = "Mozilla/8.0";

my $g_autoflush_flag;
my $g_usage =
    "$0 [sync=<on|off>] src=<local file> des=<remote file> [ip=<server server ip[:port]>] [host=<hostname>] [token=<acl token>] [timeout=<seconds>] [step=<nbytes>] [loglevel=<1..9>] [verbose=on|off]";
my $verbose;

my $paras_config = {};

&fetch_config($paras_config, @ARGV);
&check_config($paras_config, $g_usage);

$verbose = $$paras_config{"verbose"}   if ( defined($$paras_config{"verbose"}) );
if( defined($verbose) && $verbose =~/on/i )
{
    &print_config($paras_config);
}

$g_des_host     = $$paras_config{"host"}        || "store.demo.com";# default server domain
$g_des_ip       = $$paras_config{"ip"};
$g_acl_token    = $$paras_config{"token"}       || "0123456789abcdef0123456789abcdef"; # default token
$g_timeout_nsec = $$paras_config{"timeout"}     || 60;              # default timeout in seconds
$g_step_nbytes  = $$paras_config{"step"}        || 2 << 20;         # default segment size in bytes

if(defined($$paras_config{"loglevel"}))
{
    $g_log_level = $$paras_config{"loglevel"}; # loglevel range [0..9]
}

&open_fp_autoflush(\*STDOUT);
if(defined($$paras_config{"sync"}) && $$paras_config{"sync"} =~ /on/i)
{
    &upload_dir_entrance($$paras_config{"src"}, $$paras_config{"des"});
}
else
{
    &upload_file_entrance($$paras_config{"src"}, $$paras_config{"des"});
}
&restore_fp_autoflush(\*STDOUT);

################################################################################################################
# $status = upload_dir_entrance($local_dir_name, $remote_dir_name)
################################################################################################################
sub upload_dir_entrance
{
    my $status;
    my $local_dir_name;
    my $remote_dir_name;

    my $dp;

    ($local_dir_name, $remote_dir_name) = @_;

    if(! -d $local_dir_name)
    {
        &echo(0, sprintf("error:upload_dir_entrance: local dir '%s' not exist\n",
                         $local_dir_name));
        return 1; # fail
    }
    &echo(2, sprintf("[DEBUG] upload_dir_entrance: local dir '%s' exists\n",
                     $local_dir_name));

    if($local_dir_name !~ /^\//)
    {
        $local_dir_name = sprintf("%s/%s", $ENV{'PWD'}, $local_dir_name);
        &echo(2, sprintf("[DEBUG] upload_dir_entrance: local dir => '%s'\n",
                         $local_dir_name));
    }

    $status = opendir($dp, $local_dir_name);
    if(! $status)
    {
        die (sprintf("error:upload_dir_entrance: opendir '%s' failed",
                     $local_dir_name))
    }

    $status = chdir($dp);
    if(! $status)
    {
        die (sprintf("error:upload_dir_entrance: chdir '%s' failed",
                     $local_dir_name));
    }

    while(readdir($dp))
    {
        my $path_seg;
        my $local_path_name;
        my $remote_path_name;

        $path_seg = $_;

        next if ($path_seg eq "." || $path_seg eq "..");

        $local_path_name  = sprintf("%s/%s", $local_dir_name, $path_seg);
        $remote_path_name = sprintf("%s/%s", $remote_dir_name, $path_seg);

        if(-d $path_seg)
        {
            &echo(2, sprintf("[DEBUG] upload_dir_entrance: [D] '%s' -> '%s'\n",
                             $local_path_name, $remote_path_name));

            $status = &upload_dir_entrance($local_path_name, $remote_path_name);
            if(0 != $status)
            {
                closedir($dp);

                &echo(0, sprintf("error:upload_dir_entrance: sync dir '%s' -> '%s' failed\n",
                                 $local_path_name, $remote_path_name));
                return 1; # fail
            }
            &echo(1, sprintf("[DEBUG] upload_dir_entrance: sync dir '%s' -> '%s' done\n",
                             $local_path_name, $remote_path_name));

            $status = chdir($dp);
            if(! $status)
            {
                closedir($dp);

                die (sprintf("error:upload_dir_entrance: chdir '%s' again failed",
                             $local_dir_name));
            }
        }
        else
        {
            &echo(2, sprintf("[DEBUG] upload_dir_entrance: [F] '%s' -> '%s'\n",
                             $local_path_name, $remote_path_name));

            $status = &upload_file_entrance($local_path_name, $remote_path_name);
            if(0 != $status)
            {
                closedir($dp);

                &echo(0, sprintf("error:upload_dir_entrance: sync file '%s' -> '%s' failed\n",
                                 $local_path_name, $remote_path_name));
                return 1; # fail
            }
            &echo(1, sprintf("[DEBUG] upload_dir_entrance: sync file '%s' -> '%s' done\n",
                             $local_path_name, $remote_path_name));
        }
    }

    $status = closedir($dp);
    if(! $status)
    {
        die (sprintf("error:upload_dir_entrance: closedir '%s' failed",
                     $local_dir_name))
    }

    return 0; # succ
}

################################################################################################################
# $status = upload_file_entrance($local_file_name, $remote_file_name)
################################################################################################################
sub upload_file_entrance
{
    my $status;
    my $local_file_name;
    my $remote_file_name;

    ($local_file_name, $remote_file_name) = @_;

    # check src file name validity
    if(defined($local_file_name))
    {
        $status = &check_file_name_validity($local_file_name);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:upload_file_entrance: invalid src file name '%s'\n",
                             $local_file_name));
            return 1; # fail
        }
    }

    # check des file name validity
    if(defined($remote_file_name))
    {
        if($remote_file_name !~ /^\//)
        {
            $remote_file_name = "/".$remote_file_name
        }

        $status = &check_file_name_validity($remote_file_name);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:upload_file_entrance: invalid des file name '%s'\n",
                             $remote_file_name));
            return 1; # fail
        }
    }

    $status = &upload_file($local_file_name, $remote_file_name);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:upload_file_entrance: upload '%s' -> %s:%s:'%s' failed\n",
                         $local_file_name,
                         &get_remote_host(), &get_remote_ip(), $remote_file_name));
        return 1; # fail
    }

    $status = &complete_remote_file_do($remote_file_name);
    if(200 != $status)
    {
        &echo(0, sprintf("error:upload_file_entrance: upload '%s' -> %s:%s:'%s' done but push to backend failed\n",
                         $local_file_name,
                         &get_remote_host(), &get_remote_ip(), $remote_file_name));
        return 0; # fail
    }

    &echo(1, sprintf("[DEBUG] upload_file_entrance: push %s:%s:'%s' to backend done\n",
                     &get_remote_host(), &get_remote_ip(), $remote_file_name));

    &echo(1, sprintf("[DEBUG] upload_file_entrance: upload '%s' -> %s:%s:'%s' succ\n",
                     $local_file_name,
                     &get_remote_host(), &get_remote_ip(), $remote_file_name));

    if( defined($verbose) && $verbose =~/on/i )
    {
        my $local_file_size;
        my $local_file_md5;

        my $remote_file_size;
        my $remote_file_md5;

        ($status, $local_file_size)  = &size_local_file_do($local_file_name);
        &echo(0, sprintf("[DEBUG] upload_file_entrance: local  file size %d\n", $local_file_size));

        ($status, $remote_file_size) = &size_remote_file_do($remote_file_name);
        &echo(0, sprintf("[DEBUG] upload_file_entrance: remote file size %d\n", $remote_file_size));

        ($status, $local_file_md5)   = &md5_local_file_do($local_file_name,
                                                            0, $local_file_size, $local_file_size);
        &echo(0, sprintf("[DEBUG] upload_file_entrance: local  file md5 %s\n", $local_file_md5));

        ($status, $remote_file_md5)  = &md5_remote_file_do($remote_file_name,
                                                            0, $remote_file_size, $remote_file_size);
        &echo(0, sprintf("[DEBUG] upload_file_entrance: remote file md5 %s\n", $remote_file_md5));
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

    $res = $ua->get($url,
                'Host'          => &get_remote_host(),
                'Range'         => "bytes=${s_offset}-${e_offset}",
                "X-File-Size"   => ${file_size});

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
    my $remote_file_name;
    my $ua;
    my $url;
    my $res;

    ($remote_file_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("delete", $remote_file_name);

    $res = $ua->delete($url,
                'Host' => &get_remote_host());

    &echo(8, sprintf("[DEBUG] del_remote_file_do: status : %d\n", $res->code));

    return $res->code
}

################################################################################################################
# $status = upload_remote_file_do($remote_file_name, $s_offset, $e_offset, $file_size, $data)
################################################################################################################
sub upload_remote_file_do
{
    my $ua;
    my $url;
    my $res;

    my $remote_file_name;
    my $s_offset;
    my $e_offset;
    my $file_size;
    my $data;

    ($remote_file_name, $s_offset, $e_offset, $file_size, $data) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent);
    $ua->timeout($g_timeout_nsec);

    $e_offset = $e_offset - 1;

    $url = &make_url("upload", $remote_file_name);

    $res = $ua->post($url,
                'Content-Type'  => "text/html; charset=utf-8",
                Content         => $data,
                'Host'          => &get_remote_host(),
                'Range'         => "bytes=${s_offset}-${e_offset}",
                "X-File-Size"   => ${file_size});

    &echo(8, sprintf("[DEBUG] upload_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] upload_remote_file_do: headers: %s\n", $res->headers_as_string));

    &echo(2, sprintf("[DEBUG] upload_remote_file_do: %s, %d-%d/%d => %d\n",
                     $remote_file_name,
                     $s_offset, $e_offset, $file_size,
                     $res->code));

    return $res->code;
}

################################################################################################################
# $status = merge_remote_file_do($remote_file_name, $s_offset, $e_offset, $file_size)
################################################################################################################
sub merge_remote_file_do
{
    my $ua;
    my $url;
    my $res;

    my $remote_file_name;
    my $s_offset;
    my $e_offset;
    my $file_size;

    ($remote_file_name, $s_offset, $e_offset, $file_size) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent);
    $ua->timeout($g_timeout_nsec);

    $e_offset = $e_offset - 1;

    $url = &make_url("merge", $remote_file_name);

    $res = $ua->put($url,
                'Content-Type'  => "text/html; charset=utf-8",
                'Host'          => &get_remote_host(),
                'Range'         => "bytes=${s_offset}-${e_offset}",
                'X-File-Size'   => "${file_size}");

    &echo(8, sprintf("[DEBUG] merge_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] merge_remote_file_do: headers: %s\n", $res->headers_as_string));

    &echo(2, sprintf("[DEBUG] merge_remote_file_do: %s, %d-%d/%d => %d\n",
                     $remote_file_name,
                     $s_offset, $e_offset, $file_size,
                     $res->code));

    return $res->code;
}

################################################################################################################
# $status = override_remote_file_do($remote_file_name, $s_offset, $e_offset, $file_size, $data)
################################################################################################################
sub override_remote_file_do
{
    my $ua;
    my $url;
    my $res;

    my $remote_file_name;
    my $s_offset;
    my $e_offset;
    my $file_size;
    my $data;

    ($remote_file_name, $s_offset, $e_offset, $file_size, $data) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent("Mozilla/8.0");
    $ua->timeout($g_timeout_nsec);

    $e_offset = $e_offset - 1;

    $url = &make_url("override", $remote_file_name);

    $res = $ua->put($url,
                'Content-Type'  => "text/html; charset=utf-8",
                Content         => $data,
                'Host'          => &get_remote_host(),
                'Range'         => "bytes=${s_offset}-${e_offset}",
                'X-File-Size'   => ${file_size});

    &echo(8, sprintf("[DEBUG] override_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] override_remote_file_do: headers: %s\n", $res->headers_as_string));

    &echo(2, sprintf("[DEBUG] override_remote_file_do: %s, %d-%d/%d => %d\n",
                     $remote_file_name,
                     $s_offset, $e_offset, $file_size,
                     $res->code));

    return $res->code;
}

################################################################################################################
# $status = empty_remote_file_do($remote_file_name)
################################################################################################################
sub empty_remote_file_do
{
    my $remote_file_name;

    my $ua;
    my $url;
    my $res;

    ($remote_file_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("empty", $remote_file_name);

    $res = $ua->put($url,
                'Host' => &get_remote_host());

    &echo(9, sprintf("[DEBUG] empty_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] empty_remote_file_do: headers: %s\n", $res->headers_as_string));

    return $res->code;
}

################################################################################################################
# $status = complete_remote_file_do($remote_file_name)
################################################################################################################
sub complete_remote_file_do
{
    my $remote_file_name;

    my $ua;
    my $url;
    my $res;

    ($remote_file_name) = @_;

    $ua = LWP::UserAgent->new;

    $ua->agent($g_ua_agent); # pretend we are very capable browser
    $ua->timeout($g_timeout_nsec);

    $url = &make_url("complete", $remote_file_name);

    $res = $ua->get($url,
                'Host' => &get_remote_host());

    &echo(9, sprintf("[DEBUG] complete_remote_file_do: status : %d\n", $res->code));
    &echo(9, sprintf("[DEBUG] complete_remote_file_do: headers: %s\n", $res->headers_as_string));

    return $res->code;
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

    open ($fp, "<", $local_file_name) || die (sprintf("cannot open file %s", $local_file_name));
    binmode ($fp, ":bytes");

    seek($fp, $s_offset, 0) || die (sprintf("seek file %s at offset %d failed",
                                            $local_file_name, $s_offset));

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
# ($bool, $s_offset) = finger_start_seg_do($local_file_name, $remote_file_name,
#                                          $local_file_size, $remote_file_size)
################################################################################################################
sub finger_start_seg_do
{
    my $status;

    my $local_file_name;
    my $remote_file_name;
    my $local_file_size;
    my $remote_file_size;

    my $local_file_md5;
    my $remote_file_md5;

    my $s_offset;
    my $e_offset;

    ($local_file_name, $remote_file_name, $local_file_size, $remote_file_size) = @_;

    $s_offset = 0;
    while($s_offset < $local_file_size && $s_offset < $remote_file_size)
    {
        $e_offset = $s_offset + $g_step_nbytes;

        if($e_offset > $local_file_size)
        {
            $e_offset = $local_file_size;
        }

        if($e_offset > $remote_file_size)
        {
            $e_offset = $remote_file_size;
        }

        ($status, $local_file_md5) = &md5_local_file_do($local_file_name,
                                                        $s_offset, $e_offset, $local_file_size);
        if($status =~ /false/i)
        {
            return ("false", $s_offset);
        }
        &echo(2, sprintf("[DEBUG] finger_start_seg_do: md5 local file %s %d-%d/%d is %s\n",
                        $local_file_name, $s_offset, $e_offset, $local_file_size, $local_file_md5));


        ($status, $remote_file_md5) = &md5_remote_file_do($remote_file_name,
                                                          $s_offset, $e_offset, $remote_file_size);
        if(200 != $status)
        {
            return ("false", $s_offset);
        }

        &echo(2, sprintf("[DEBUG] finger_start_seg_do: md5 remote file %s %d-%d/%d is %s\n",
                        $remote_file_name, $s_offset, $e_offset, $remote_file_size, $remote_file_md5));

        if($local_file_md5 ne $remote_file_md5)
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
#                                  $s_offset, $e_offset, $local_file_size)
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

    my $data;
    my $fp;

    ($local_file_name, $remote_file_name, $s_offset, $e_offset, $local_file_size) = @_;

    $s_offset_t = $s_offset;

    open ($fp, "<", $local_file_name) || die (sprintf("error:append_file: cannot open file %s",
                                                      $local_file_name));
    binmode ($fp, ":bytes");

    seek($fp, $s_offset_t, 0) || die (sprintf("error:append_file: seek file %s at offset %d failed",
                                              $local_file_name, $s_offset_t));

    while($s_offset_t < $e_offset && $s_offset_t < $local_file_size)
    {
        $e_offset_t = $s_offset_t + $g_step_nbytes;
        if($e_offset_t > $e_offset)
        {
            $e_offset_t = $e_offset;
        }
        if($e_offset_t > $local_file_size)
        {
            $e_offset_t = $local_file_size;
        }

        if(read($fp, $data, $e_offset_t - $s_offset_t) <= 0)
        {
            close($fp);

            &echo(0, sprintf("error:append_file: read local file %s %d-%d failed\n",
                             $local_file_name, $s_offset_t, $e_offset_t));
            return ("false", $s_offset_t);
        }

        $status = &upload_remote_file_do($remote_file_name,
                                         $s_offset_t, $e_offset_t, $local_file_size,
                                         $data);
        if(200 != $status)
        {
            close($fp);

            &echo(0, sprintf("error:append_file: append %s %d-%d/%d failed, status %d\n",
                             $remote_file_name, $s_offset_t, $e_offset_t,
                             $local_file_size, $status));

            return ("false", $s_offset_t);
        }
        &echo(9, sprintf("[DEBUG] append_file: append %s %d-%d/%d done\n",
                         $remote_file_name, $s_offset_t, $e_offset_t, $local_file_size));

        $status = &merge_remote_file_do($remote_file_name,
                                        $s_offset_t, $e_offset_t, $local_file_size);
        if(200 != $status)
        {
            close($fp);

            &echo(0, sprintf("error:append_file: merge %s %d-%d/%d failed, status %d\n",
                             $remote_file_name, $s_offset_t, $e_offset_t,
                             $local_file_size, $status));
            return ("false", $s_offset_t);
        }
        &echo(9, sprintf("[DEBUG] append_file: merge %s %d-%d/%d done\n",
                      $remote_file_name, $s_offset_t, $e_offset_t, $local_file_size));

        &echo(1, sprintf("[DEBUG] append_file: append %s, %d-%d/%d => complete %.2f%%\n",
                         $remote_file_name,
                         $s_offset_t, $e_offset_t, $local_file_size,
                         100.0 * ($e_offset_t + 0.0) / ($local_file_size + 0.0)));

        $s_offset_t = $e_offset_t;
    }

    close($fp);

    return ("true", $s_offset_t);
}

################################################################################################################
# ($bool, $s_offset) = override_file($local_file_name, $remote_file_name,
#                                    $s_offset, $e_offset,
#                                    $local_file_size, $remote_file_size)
################################################################################################################
sub override_file
{
    my $status;

    my $local_file_name;
    my $remote_file_name;
    my $local_file_size;
    my $remote_file_size;

    my $s_offset;
    my $e_offset;

    my $s_offset_t;
    my $e_offset_t;

    my $data;
    my $fp;

    ($local_file_name, $remote_file_name, $s_offset, $e_offset, $local_file_size, $remote_file_size) = @_;

    $s_offset_t = $s_offset;

    open ($fp, "<", $local_file_name) || die (sprintf("error:override_file: cannot open file %s",
                                                      $local_file_name));
    binmode ($fp, ":bytes");

    seek($fp, $s_offset_t, 0) || die (sprintf("error:override_file: seek file %s at offset %d failed",
                                              $local_file_name, $s_offset_t));

    while($s_offset_t < $e_offset
    && $s_offset_t < $local_file_size
    && $s_offset_t < $remote_file_size)
    {
        $e_offset_t = $s_offset_t + $g_step_nbytes;
        if($e_offset_t > $e_offset)
        {
            $e_offset_t = $e_offset;
        }
        if($e_offset_t > $local_file_size)
        {
            $e_offset_t = $local_file_size;
        }
        if($e_offset_t > $remote_file_size)
        {
            $e_offset_t = $remote_file_size;
        }

        if(read($fp, $data, $e_offset_t - $s_offset_t) <= 0)
        {
            close($fp);
            &echo(0, sprintf("error:override_file: read local file %s %d-%d failed\n",
                             $local_file_name, $s_offset_t, $e_offset_t));

            return ("false", $s_offset_t);
        }

        $status = &override_remote_file_do($remote_file_name,
                                           $s_offset_t, $e_offset_t, $local_file_size,
                                           $data);
        if(200 != $status)
        {
            close($fp);
            &echo(0, sprintf("error:override_file: override %s %d-%d/%d failed, status %d\n",
                             $remote_file_name, $s_offset_t, $e_offset_t,
                             $local_file_size, $status));

            return ("false", $s_offset_t);
        }
        &echo(9, sprintf("[DEBUG] override_file: override %s %d-%d/%d done\n",
                      $remote_file_name, $s_offset_t, $e_offset_t, $local_file_size));

        &echo(1, sprintf("[DEBUG] override_file: override %s, %d-%d/%d => complete %.2f%%\n",
                         $remote_file_name,
                         $s_offset_t, $e_offset_t, $local_file_size,
                         100.0 * ($e_offset_t + 0.0) / ($local_file_size + 0.0)));

        $s_offset_t = $e_offset_t;
    }

    close($fp);

    return ("true", $s_offset_t);
}

################################################################################################################
# $bool = upload_file($local_file_name, $remote_file_name)
################################################################################################################
sub upload_file
{
    my $status;
    my $code;

    my $local_file_name;
    my $remote_file_name;

    my $local_file_size;
    my $local_file_md5;

    my $remote_file_size;
    my $remote_file_md5;

    my $data;
    my $s_offset;
    my $e_offset;

    my $fp;

    ($local_file_name, $remote_file_name) = @_;

    ($status, $local_file_size) = &size_local_file_do($local_file_name);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:upload_file: not found %s\n", $local_file_name));
        return "false";
    }

    ($code, $remote_file_size) = &size_remote_file_do($remote_file_name);
    &echo(9, sprintf("[DEBUG] upload_file: [remote] code: %d, size: %d\n", $code, $remote_file_size));

    # remote file exist
    if(200 == $code)
    {
        &echo(9, sprintf("[DEBUG] upload_file: local file size: %d, remote file size: %d\n",
                         $local_file_size, $remote_file_size));

        if(0 == $local_file_size)
        {
            if(0 < $remote_file_size)
            {
                $status = &empty_remote_file_do($remote_file_name);
                if(200 != $status)
                {
                    &echo(0, sprintf("error:upload_file: empty remote file %s failed, status %d\n",
                                     $remote_file_name, $status));
                    return "false";
                }
                &echo(1, sprintf("[DEBUG] upload_file: empty remote file %s done\n",
                                 $remote_file_name));
            }
            &echo(1, sprintf("[DEBUG] upload_file: empty file => succ\n"));
            return "true";
        }

        if($local_file_size < $remote_file_size)
        {
            $status = &del_remote_file_do($remote_file_name);
            if(200 != $status)
            {
                &echo(0, sprintf("error:upload_file: del remote file %s failed, status %d\n",
                                 $remote_file_name, $status));
                return "false";
            }

            $s_offset = 0;

            &echo(1, sprintf("[DEBUG] upload_file: local file size %d < remote file size %ld, del remote file %s done\n",
                              $local_file_size, $remote_file_size, $remote_file_name));
        }
        elsif(0 == $remote_file_size)
        {
            $s_offset = 0;
        }
        else # $local_file_size >= $remote_file_size && $remote_file_size > 0
        {
            ($status, $local_file_md5) = &md5_local_file_do($local_file_name,
                                                        0, $remote_file_size, $local_file_size);
            if($status =~ /false/i)
            {
                &echo(0, sprintf("error:upload_file: md5 local file %s, %d-%d/%d failed\n",
                                 $local_file_name, 0, $remote_file_size, $local_file_size));
                return "false";
            }
            &echo(1, sprintf("[DEBUG] upload_file: md5 %d-%d/%d => %s, local  file %s\n",
                             0, $remote_file_size, $local_file_size,
                             $local_file_md5,
                             $local_file_name));

            ($status, $remote_file_md5) = &md5_remote_file_do($remote_file_name,
                                                            0, $remote_file_size, $remote_file_size);
            if(200 != $status)
            {
                &echo(0, sprintf("error:upload_file: md5 remote file %s failed\n", $remote_file_name));
                return "false";
            }
            &echo(1, sprintf("[DEBUG] upload_file: md5 %d-%d/%d => %s, remote file %s\n",
                             0, $remote_file_size, $remote_file_size,
                             $remote_file_md5,
                             $remote_file_name));

            if($local_file_md5 eq $remote_file_md5)
            {
                if($local_file_size == $remote_file_size)
                {
                    &echo(2, sprintf("[DEBUG] upload_file: same file => succ\n"));
                    return "true";
                }

                $s_offset = 0;
                $e_offset = $remote_file_size;

                &echo(1, sprintf("[DEBUG] upload_file: skip %s, %d-%d/%d => complete %.2f%%\n",
                                 $remote_file_name,
                                 $s_offset, $e_offset, $local_file_size,
                                 100.0 * ($e_offset + 0.0) / ($local_file_size + 0.0)));

                $s_offset = $remote_file_size;
            }
            else
            {
                ($status, $s_offset) = &finger_start_seg_do($local_file_name, $remote_file_name,
                                                            $local_file_size, $remote_file_size);
                if($status =~ /false/i)
                {
                    &echo(0, sprintf("error:upload_file: file %s, finger start seg failed, s_offset = %d\n",
                                    $local_file_name, $s_offset));
                    return "false";
                }
                &echo(1, sprintf("[DEBUG] upload_file: file %s, finger start seg done, s_offset = %d\n",
                                 $local_file_name, $s_offset));

                ($status, $s_offset) = &override_file($local_file_name, $remote_file_name,
                                                      $s_offset, $remote_file_size,
                                                      $local_file_size, $remote_file_size);
                if($status =~ /false/i)
                {
                    &echo(0, sprintf("error:upload_file: file %s, override failed, s_offset = %d\n",
                                     $local_file_name, $s_offset));
                    return ("false", );
                }
                &echo(1, sprintf("[DEBUG] upload_file: file %s, override done, s_offset = %d\n",
                                 $local_file_name, $s_offset));
            }
        }
    }
    # remote file not exist
    else
    {
        $s_offset = 0;
    }

    # optimize: alignment
    if(0 != ($s_offset % $g_step_nbytes))
    {
        $e_offset = $s_offset + $g_step_nbytes - ($s_offset % $g_step_nbytes);
        if($e_offset > $local_file_size)
        {
            $e_offset = $local_file_size;
        }

        ($status, $s_offset) = &append_file($local_file_name, $remote_file_name,
                                            $s_offset, $e_offset, $local_file_size);
        if($status =~ /false/i)
        {
            &echo(0, sprintf("error:upload_file: file %s, append seg failed, s_offset = %d\n",
                             $local_file_name, $s_offset));
            return "false";
        }
    }

    ($status, $s_offset) = &append_file($local_file_name, $remote_file_name,
                                        $s_offset, $local_file_size, $local_file_size);
    if($status =~ /false/i)
    {
        &echo(0, sprintf("error:upload_file: file %s, append failed, s_offset = %d\n",
                         $local_file_name, $s_offset));
        return "false";
    }

    &echo(1, sprintf("[DEBUG] upload_file: upload %s done\n", $remote_file_name));
    return "true";
}

################################################################################################################
# $url = make_url($op, $remote_path)
################################################################################################################
sub make_url
{
    my $op;
    my $remote_path;
    my $time;
    my $md5;

    ($op, $remote_path) = @_;

    $time = sprintf("%s", time() + $g_expired_nsec);

    $md5  = md5_hex(sprintf("%s@%s%s@%s", $g_acl_token, $op, $remote_path, $time));

    &echo(9, sprintf("[DEBUG] make_url: %s@%s%s@%s => md5 %s\n",
                    $g_acl_token, $op, $remote_path, $time, $md5));

    return sprintf("http://%s/%s?op=%s&sig=%s&t=%s",
                    &get_remote_ip() || &get_remote_host(),
                    $remote_path, $op, $md5, $time);
}

################################################################################################################
# $ip = get_remote_ip()
################################################################################################################
sub get_remote_ip
{
    return $g_des_ip || &get_remote_host();
}


################################################################################################################
# $host = get_remote_host()
################################################################################################################
sub get_remote_host
{
    return $g_des_host;
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

