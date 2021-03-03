#! /usr/bin/perl -w

################################################################################################################
# description:  collect and set mapping of macro definition and (file name, line no)
# version    :  v0.3
# creator    :  Chaoyong Zhou
#
# History:
#    1. 03/18/2011: v0.1, created
#    2. 06/22/2011: v0.2, support macro with __file__, __line__
#    3. 09/11/2011: v0.3, replace __file__, __line__ with __location__
################################################################################################################

use strict;

my $g_usage = "$0 dir_list=<dir1[,dir2,...]> [postfixs=<posfix list seperated by comma>] [macro_file=<macro file>] [loc_tbl_file=<macro and location table file>] [deny_reason_file=<deny reason file>] copyright=<copyright file> [verbose=on|off]";

# usage example:
#  perl tool/set_macro_fname_lineno.pl dir_list=bgn_src:rel_src:custom:ngx_src:amd_src postfixs=".c" macro_file=bgn_inc/loc_macro.inc loc_tbl_file=bgn_inc/loc_tbl.inc deny_reason_file=bgn_inc/deny_reason.inc copyright=copyright

my %g_err_code =
(
    "no_err"            =>   0,#
    "err_log_bug"       =>   2,#
    "err_keyword"       =>   4,#
    "err_hash_key"      =>   8,#
    "err_args"          =>  16,#
    "err_reset_type"    =>  32,#
    "err_no_file"       =>  64,#
    "err_no_dir"        =>  65,#
    "err_open_file"     => 128,#
    "err_read_file"     => 256,#
    "err_write_file"    => 512,#
    "err_undef"         => 110,#

);

my $g_tab = "  ";
my $g_autoflush_flag;

my $g_location_tbl = {};
my $g_deny_reason_tbl = {};

my $verbose;
my $paras_config = {};

open_fp_autoflush(\*STDOUT);

&fetch_config($paras_config, @ARGV);
&check_config($paras_config, $g_usage);
&print_config($paras_config);

assert_file_exist($$paras_config{"copyright"});

#&assert_dir_exist($$paras_config{"dir_list"});
$verbose   = $$paras_config{"verbose"} if ( defined($$paras_config{"verbose"}) );

&main($$paras_config{"dir_list"}, $$paras_config{"postfixs"});

################################################################################################################
# main($dir_name, $postfixs_str)
################################################################################################################
sub main
{
    my $dir_list;
    my $postfixs_str;

    my $postfixs;
    my $files_t;
    my $files;

    ($dir_list, $postfixs_str) = @_;

    if(defined($postfixs_str))
    {
        $postfixs = [];
        @$postfixs = split(',', $postfixs_str);
    }

    $files_t = [];
    $files = [];
    #&collect_files_of_dir($dir_list, $postfixs, $files);
    &collect_files_of_dir_list($dir_list, $postfixs, $files_t);
    @$files = sort { $a cmp $b } @$files_t;
    #push(@$files, "src/task.c");
    #&print_files(\*STDOUT, $files);

    #&dos2unix_of_files($files);
    &discard_tail_space_of_files($files);

    #&conv_file_to_log_of_files($files);
    &update_macro_location_of_files($files);
    #&update_macro_fname_lineno_of_files($files);
    #&set_macro_fname_lineno_of_files($files);
    &update_deny_reason_of_files($files);
    #&append_lost_line_of_files($files);
}

################################################################################################################
# conv_file_to_log_of_files(@files)
################################################################################################################
sub conv_file_to_log_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("conv_file_to_log_of_files: handle file: %s\n", $file);
        &conv_file_to_log_of_file($file);
    }
}

################################################################################################################
# conv_file_to_log_of_file($file)
################################################################################################################
sub conv_file_to_log_of_file
{
    my $file;

    my $fp;

    my $lines;
    my $line;

    my $line_num;
    my $line_idx;

    ($file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "update_macro_location_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    open($fp,"> $file") || &com_die("err_write_file", "update_macro_location_of_file: cannot open $file to write\n");
    #$fp = \*STDOUT;

    $line_num = scalar(@$lines);
    for($line_idx = 0; $line_idx < $line_num; )
    {
        $line = $$lines[ $line_idx ];
        $line_idx ++;

        chomp($line);
        $line = &conv_file_to_log_of_line($file, $line_idx, $line);

        printf $fp ("%s\n", $line);
    }
    close($fp);
}

################################################################################################################
# conv_file_to_log_of_line($file, $lineno, $line)
################################################################################################################
sub conv_file_to_log_of_line
{
    my $file;
    my $lineno;
    my $line;

    ($file, $lineno, $line) = @_;

    if($line !~ /#define/ && $line !~ /#include/ && $line !~ /typedef/ && $line =~/fp/)
    {
        if(0)
        {
            $line =~ s/FILE/LOG/g;
        }
        if(0)
        {
            if($line =~ /\*fp/ && $line !~ /\*fp\S+/)
            {
                $line =~ s/\*fp/\*log/g;
            }

            if($line =~ /fp,/ && $line !~ /\S+fp,/)
            {
                $line =~ s/fp,/log,/g;
            }
            if($line =~ /\*fp,/)
            {
                $line =~ s/\*fp,/\*log,/g;
            }
            if($line =~ /\(fp,/)
            {
                $line =~ s/\(fp,/\(log,/g;
            }
            if($line =~ /\*fp\)/)
            {
                $line =~ s/\*fp\)/\*log\)/g;
            }
            if($line =~ /\(fp\)/)
            {
                $line =~ s/\(fp\)/\(log\)/g;
            }
        }
    }
    if(1)
    {
        $line =~ s/stdout/LOGSTDOUT/g;
        $line =~ s/stderr/LOGSTDERR/g;
        $line =~ s/stdin/LOGSTDIN/g;
    }
    return $line;
}

################################################################################################################
# update_deny_reason_fname_lineno_of_files(@files)
################################################################################################################
sub update_deny_reason_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("update_deny_reason_of_files: handle file: %s\n", $file);
        &update_deny_reason_of_file($file);
    }

    &print_deny_reason_tbl();
}

################################################################################################################
# update_deny_reason_of_file($file)
################################################################################################################
sub update_deny_reason_of_file
{
    my $file;

    my $fp;

    my $lines;
    my $line;

    my $line_num;
    my $line_idx;

    ($file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "update_deny_reason_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    open($fp,"> $file") || &com_die("err_write_file", "update_deny_reason_of_file: cannot open $file to write\n");
    #$fp = \*STDOUT;

    $line_num = scalar(@$lines);
    for($line_idx = 0; $line_idx < $line_num; )
    {
        $line = $$lines[ $line_idx ];
        $line_idx ++;

        chomp($line);
        $line = &update_deny_reason_of_line($file, $line_idx, $line);

        printf $fp ("%s\n", $line);
    }
    close($fp);
}

################################################################################################################
# update_deny_reason_of_line($file, $lineno, $line)
################################################################################################################
sub update_deny_reason_of_line
{
    my $file;
    my $lineno;
    my $line;

    my $tag;

    my $deny_reason;

    ($file, $lineno, $line) = @_;

    if($line =~ /#define/) # skip
    {
        return $line;
    }

    if($line =~ /DENY_REASON_[A-Z0-9]+_[0-9]+/)
    {
        #printf STDOUT "%s\n", $line;
        $deny_reason = &gen_deny_reason($file, $lineno);
        $line =~ s/DENY_REASON_[A-Z0-9]+_[0-9]+/$deny_reason/g;
        #printf STDOUT "==> %s\n", $line;
    }
    return $line;
}

################################################################################################################
# gen_deny_reason($file, $lineno)
################################################################################################################
sub gen_deny_reason
{
    my $file;
    my $lineno;

    my $short_file;
    my $file_scope;
    my $deny_reason;
    my $deny_reason_rec_list;
    my $deny_reason_rec;

    ($file, $lineno) = @_;

    $short_file = base_name($file);
    $short_file =~s/\//_/g;  # '/' -> '_'
    $short_file =~s/\\/_/g;  # '\' -> '_'
    $short_file =~s/\..*//g; # "x.y.z" -> "x"
    $short_file =~s/_.*//g;  # "x_y_z" -> "x"

    if(!defined($$g_deny_reason_tbl{ $short_file }))
    {
        $$g_deny_reason_tbl{ $short_file } = {};

        $file_scope = $$g_deny_reason_tbl{ $short_file };
        $$file_scope{"deny_reason_pos"} = 0;
        $$file_scope{"deny_reason_rec"} = [];
    }

    $file_scope = $$g_deny_reason_tbl{ $short_file };
    $$file_scope{"deny_reason_pos"} ++;

    #$deny_reason = $$file_scope{"deny_reason_pos"};
    $deny_reason = sprintf("DENY_REASON_%s_%04d", uc($short_file), $$file_scope{"deny_reason_pos"});

    $deny_reason_rec = {};
    $$deny_reason_rec{"filename"} = $file;
    $$deny_reason_rec{"lineno"  } = $lineno;
    $$deny_reason_rec{"deny_reason"} = $deny_reason;

    $deny_reason_rec_list = $$file_scope{"deny_reason_rec"};
    push(@$deny_reason_rec_list, $deny_reason_rec);

    #$deny_reason = sprintf("LOC_%s_%04d", uc($short_file), $deny_reason);
    return $deny_reason;
}

################################################################################################################
# update_macro_fname_lineno_of_files(@files)
################################################################################################################
sub update_macro_location_of_files
{
    my $files;

    my $file;
    my $tags;

    ($files) = @_;

    $tags = [];
    &create_tag_table($tags);

    foreach $file (@$files)
    {
        printf STDOUT ("update_macro_location_of_files: handle file: %s\n", $file);
        &update_macro_location_of_file($tags, $file);
    }

    &print_location_tbl();
}

################################################################################################################
# update_macro_location_of_file(@tags, $file)
################################################################################################################
sub update_macro_location_of_file
{
    my $tags;
    my $file;

    my $fp;

    my $lines;
    my $line;

    my $line_num;
    my $line_idx;

    ($tags, $file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "update_macro_location_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    open($fp,"> $file") || &com_die("err_write_file", "update_macro_location_of_file: cannot open $file to write\n");
    #$fp = \*STDOUT;

    $line_num = scalar(@$lines);
    for($line_idx = 0; $line_idx < $line_num; )
    {
        $line = $$lines[ $line_idx ];
        $line_idx ++;

        chomp($line);
        $line = &update_macro_location_of_line($tags, $file, $line_idx, $line);

        printf $fp ("%s\n", $line);
    }
    close($fp);
}

################################################################################################################
# update_macro_location_of_line(@tags, $file, $lineno, $line)
################################################################################################################
sub update_macro_location_of_line
{
    my $tags;
    my $file;
    my $lineno;
    my $line;

    my $tag;

    my $location;

    ($tags, $file, $lineno, $line) = @_;

    if($line =~ /#define/ || $line =~ /location\);/ || $line =~ /__location__/) # skip
    {
        return $line;
    }

    # patch!
    # deprecate this patch on Apr 22, 2013
    #if($line =~ /_location_/)
    #{
    #    $location = &gen_location($file, $lineno);
    #    $line =~ s/_location_/$location/g;
    #    return $line;
    #}

    #if($line !~ /\);/ && $line !~ /LOC_[A-Z0-9]+_[0-9]+\)/)
    #{
    #    return $line;
    #}

    if(0)
    {
        foreach $tag (@$tags)
        {
            if($line =~ /$tag\(/ || $line =~ /$tag\s+\(/)
            {
                #printf STDOUT ("handle line: %s\n", $line);
                $location = &gen_location($file, $lineno);

                if($line =~ /\);/)
                {

                    $line =~ s/,[^,]+\);/, $location\);/;
                }
                else
                {
                    printf STDOUT ("handle line: %s\n", $line);
                    $line =~ s/,\s*LOC_[A-Z0-9]+_[0-9]+/, $location/;
                }
                $line =~ s/\(\s+/\(/g;
            }
        }
    }

    if($line =~ /LOC_[A-Z0-9_]+_[0-9]+/)
    {
        #printf STDOUT "%s\n", $line;
        $location = &gen_location($file, $lineno);
        $line =~ s/LOC_[A-Z0-9_]+_[0-9]+/$location/g;
        #printf STDOUT "==> %s\n", $line;
    }
    return $line;
}

################################################################################################################
# gen_location($file, $lineno)
################################################################################################################
sub gen_location
{
    my $file;
    my $lineno;

    my $short_file;
    my $file_scope;
    my $location;
    my $location_rec_list;
    my $location_rec;

    ($file, $lineno) = @_;

    $short_file = base_name($file);
    $short_file =~s/\//_/g;  # '/' -> '_'
    $short_file =~s/\\/_/g;  # '\' -> '_'
    $short_file =~s/\..*//g; # "x.y.z" -> "x"
    $short_file =~s/_.*//g;  # "x_y_z" -> "x"

    if(!defined($$g_location_tbl{ $short_file }))
    {
        $$g_location_tbl{ $short_file } = {};

        $file_scope = $$g_location_tbl{ $short_file };
        $$file_scope{"location_pos"} = 0;
        $$file_scope{"location_rec"} = [];
    }

    $file_scope = $$g_location_tbl{ $short_file };
    $$file_scope{"location_pos"} ++;

    #$location = $$file_scope{"location_pos"};
    $location = sprintf("LOC_%s_%04d", uc($short_file), $$file_scope{"location_pos"});

    $location_rec = {};
    $$location_rec{"filename"} = $file;
    $$location_rec{"lineno"  } = $lineno;
    $$location_rec{"location"} = $location;

    $location_rec_list = $$file_scope{"location_rec"};
    push(@$location_rec_list, $location_rec);

    #$location = sprintf("LOC_%s_%04d", uc($short_file), $location);
    return $location;
}

################################################################################################################
# print_copyright($fp)
################################################################################################################
sub print_copyright
{
    my $fp;

    my $copyright_fname;
    my $copyright_fp;

    my $lines;
    my $line;

    ($fp) = @_;

    $copyright_fname = $$paras_config{"copyright"};

    open($copyright_fp, "< $copyright_fname") || &com_die("err_read_file", "print_copyright: cannot open $copyright_fname to read\n");
    $lines = [];
    @$lines = <$copyright_fp>;
    close($copyright_fp);

    foreach $line (@$lines)
    {
        printf $fp ("$line");
    }
}

################################################################################################################
# print_deny_reason_tbl()
################################################################################################################
sub print_deny_reason_tbl
{
    my $short_file;
    my $file_scope;
    my $deny_reason_rec_list;
    my $deny_reason_rec;

    my $file_name;

    my $macro_name;
    my $macro_val;

    my $deny_reason_file;

    my $fp_macro;

    my $na_str;
    my $na_val;

    $na_str = "\"NA\"";
    $na_val = 0;

    if(defined($$paras_config{"deny_reason_file"}))
    {
        $deny_reason_file   = $$paras_config{"deny_reason_file"};
        open($fp_macro,"> $deny_reason_file")   || &com_die("err_write_file", "print_deny_reason_tbl: cannot open $deny_reason_file to write\n");
    }
    else
    {
        $fp_macro = \*STDOUT;
    }

    ## put copyright at first lines
    &print_copyright($fp_macro);

    printf $fp_macro ("#ifndef _DENY_REASON_INC_\n");
    printf $fp_macro ("#define _DENY_REASON_INC_\n");
    #printf $fp_macro ("#include \"type.h\"\n");


    $macro_val = 0;

    $macro_name = "DENY_REASON_NONE_BASE";
    printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_name, $macro_val);

    $macro_val ++;


    foreach $short_file (keys (%$g_deny_reason_tbl))
    {
        $file_scope = $$g_deny_reason_tbl{ $short_file };

        $deny_reason_rec_list = $$file_scope{"deny_reason_rec"};

        foreach $deny_reason_rec (@$deny_reason_rec_list)
        {
            $file_name = sprintf("\"%s\"", $$deny_reason_rec{"filename"});

            $macro_name = $$deny_reason_rec{"deny_reason"};
            printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_name, $macro_val);
            $macro_val ++;
        }
    }

    $macro_name = "DENY_REASON_NONE_END";
    printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_name, $macro_val);
    $macro_val ++;

    printf $fp_macro ("#endif/*_DENY_REASON_INC_*/\n");

    if($fp_macro != \*STDOUT)
    {
        close($fp_macro);
    }
}


################################################################################################################
# print_location_tbl()
################################################################################################################
sub print_location_tbl
{
    my $short_file;
    my $file_scope;
    my $location_rec_list;
    my $location_rec;

    my $file_name;

    my $macro_name;
    my $macro_val;

    my $macro_file;
    my $loc_tbl_file;

    my $fp_macro;
    my $fp_loc_tbl;

    my $na_str;
    my $na_val;

    $na_str = "\"NA\"";
    $na_val = 0;

    if(defined($$paras_config{"macro_file"}))
    {
        $macro_file   = $$paras_config{"macro_file"};
        open($fp_macro,"> $macro_file")   || &com_die("err_write_file", "print_location_tbl: cannot open $macro_file to write\n");
    }
    else
    {
        $fp_macro = \*STDOUT;
    }

    ## put copyright at first lines
    &print_copyright($fp_macro);

    printf $fp_macro ("#ifndef _LOC_MACRO_INC_\n");
    printf $fp_macro ("#define _LOC_MACRO_INC_\n");
    #printf $fp_macro ("#include \"type.h\"\n");

    if(defined($$paras_config{"loc_tbl_file"}))
    {
        $loc_tbl_file = $$paras_config{"loc_tbl_file"};
        open($fp_loc_tbl,"> $loc_tbl_file") || &com_die("err_write_file", "print_location_tbl: cannot open $loc_tbl_file to write\n");
    }
    else
    {
        $fp_loc_tbl = \*STDOUT;
    }

    ## put copyright at first lines
    &print_copyright($fp_loc_tbl);

    printf $fp_loc_tbl ("#ifndef _LOC_TBL_INC_\n");
    printf $fp_loc_tbl ("#define _LOC_TBL_INC_\n");

    $macro_val = 0;

    $macro_name = "LOC_NONE_BASE";
    printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_name, $macro_val);
    printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_name, $na_str, $na_val);

    $macro_val ++;


    foreach $short_file (keys (%$g_location_tbl))
    {
        $file_scope = $$g_location_tbl{ $short_file };

        $location_rec_list = $$file_scope{"location_rec"};

        foreach $location_rec (@$location_rec_list)
        {
            $file_name = sprintf("\"%s\"", $$location_rec{"filename"});

            $macro_name = $$location_rec{"location"};
            printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_name, $macro_val);
            printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_name, $file_name, $$location_rec{"lineno"});
            $macro_val ++;
        }
    }

    $macro_name = "LOC_NONE_END";
    printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_name, $macro_val);
    printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_name, $na_str, $na_val);
    $macro_val ++;


    printf $fp_macro ("#endif/*_LOC_MACRO_INC_*/\n");

    if($fp_macro != \*STDOUT)
    {
        close($fp_macro);
    }

    printf $fp_loc_tbl ("#endif/*_LOC_TBL_INC_*/\n");
    if($fp_loc_tbl != \*STDOUT)
    {
        close($fp_loc_tbl);
    }
}

################################################################################################################
# print_location_tbl_0()
################################################################################################################
sub print_location_tbl_0
{
    my $short_file;
    my $file_scope;
    my $location_rec_list;
    my $location_rec;

    my $macro_val_offset;
    my $macro_val_head;
    my $macro_val_tail;
    my $macro_val_base;
    my $macro_val_end;
    my $file_name;

    my $macro_file;
    my $loc_tbl_file;

    my $fp_macro;
    my $fp_loc_tbl;

    my $na;

    $na = "\"NA\"";
    #$macro_val_base = 0;
    #foreach $short_file (keys (%$g_location_tbl))
    #{
    #    $file_scope = $$g_location_tbl{ $short_file };
    #
    #    $macro_val_start = sprintf("LOC_%s_0000", uc($short_file));
    #
    #    printf STDOUT ("#define %-32s    ((UINT32)(%8ld))\n", $macro_val_start, $macro_val_base);
    #
    #    $macro_val_base ++;
    #}

    if(defined($$paras_config{"macro_file"}))
    {
        $macro_file   = $$paras_config{"macro_file"};
        open($fp_macro,"> $macro_file")   || &com_die("err_write_file", "print_location_tbl: cannot open $macro_file to write\n");
    }
    else
    {
        $fp_macro = \*STDOUT;
    }
    printf $fp_macro ("#ifndef _LOC_MACRO_INC_\n");
    printf $fp_macro ("#define _LOC_MACRO_INC_\n");
    #printf $fp_macro ("#include \"type.h\"\n");

    if(defined($$paras_config{"loc_tbl_file"}))
    {
        $loc_tbl_file = $$paras_config{"loc_tbl_file"};
        open($fp_loc_tbl,"> $loc_tbl_file") || &com_die("err_write_file", "print_location_tbl: cannot open $loc_tbl_file to write\n");
    }
    else
    {
        $fp_loc_tbl = \*STDOUT;
    }
    printf $fp_loc_tbl ("#ifndef _LOC_TBL_INC_\n");
    printf $fp_loc_tbl ("#define _LOC_TBL_INC_\n");

    $macro_val_base = "LOC_NONE_BASE";
    printf $fp_macro ("#define %-32s    ((UINT32)(%8ld))\n", $macro_val_base, 0);
    printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_val_base, $na, 0);

    foreach $short_file (keys (%$g_location_tbl))
    {
        $file_scope = $$g_location_tbl{ $short_file };
        $macro_val_offset = 1;

        $macro_val_head = sprintf("LOC_%s_HEAD", uc($short_file));
        printf $fp_macro ("#define %-32s    ((UINT32)(%-16s + %8ld))\n", $macro_val_head, $macro_val_base, $macro_val_offset);
        printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_val_head, $na, 0);

        $macro_val_offset ++;

        $location_rec_list = $$file_scope{"location_rec"};

        foreach $location_rec (@$location_rec_list)
        {
            $file_name = sprintf("\"%s\"", $$location_rec{"filename"});

            printf $fp_macro ("#define %-32s    ((UINT32)(%-16s + %8ld))\n", $$location_rec{"location"}, $macro_val_head, $macro_val_offset);
            printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $$location_rec{"location"}, $file_name, $$location_rec{"lineno"});

            $macro_val_offset ++;
        }

        $macro_val_tail = sprintf("LOC_%s_TAIL", uc($short_file));
        printf $fp_macro ("#define %-32s    ((UINT32)(%-16s + %8ld))\n", $macro_val_tail, $macro_val_head, $macro_val_offset);
        printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_val_tail, $na, 0);

        $macro_val_base = $macro_val_tail;
    }

    $macro_val_end = "LOC_NONE_END";
    printf $fp_macro ("#define %-32s    ((UINT32)(%-16s + %8ld))\n", $macro_val_end, $macro_val_tail, 1);
    printf $fp_loc_tbl ("{%-16s, %-32s, %8d},\n", $macro_val_end, $na, 0);

    printf $fp_macro ("#endif/*_LOC_MACRO_INC_*/\n");

    if($fp_macro != \*STDOUT)
    {
        close($fp_macro);
    }

    printf $fp_loc_tbl ("#endif/*_LOC_TBL_INC_*/\n");
    if($fp_loc_tbl != \*STDOUT)
    {
        close($fp_loc_tbl);
    }
}

################################################################################################################
# update_macro_fname_lineno_of_files(@files)
################################################################################################################
sub update_macro_fname_lineno_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("update_macro_fname_lineno_of_files: handle file: %s\n", $file);
        &update_macro_fname_lineno_of_file($file);
    }
}

################################################################################################################
# update_macro_fname_lineno_of_file($file)
################################################################################################################
sub update_macro_fname_lineno_of_file
{
    my $file;

    my $fp;

    my $lines;
    my $line;

    my $line_num;
    my $line_idx;

    ($file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "update_macro_fname_lineno_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    open($fp,"> $file") || &com_die("err_write_file", "update_macro_fname_lineno_of_file: cannot open $file to write\n");
    #$fp = \*STDOUT;

    $line_num = scalar(@$lines);
    for($line_idx = 0; $line_idx < $line_num; )
    {
        $line = $$lines[ $line_idx ];
        $line_idx ++;

        chomp($line);
        $line = &update_macro_fname_lineno_of_line($file, $line_idx, $line);

        printf $fp ("%s\n", $line);
    }
    close($fp);
}

################################################################################################################
# update_macro_fname_lineno_of_line($file, $lineno, $line)
################################################################################################################
sub update_macro_fname_lineno_of_line
{
    my $file;
    my $lineno;

    my $line;

    my $tags;
    my $tag;

    ($file, $lineno, $line) = @_;

    $tags = [];

    &create_tag_table($tags);

    foreach $tag (@$tags)
    {
        if($line =~ /$tag\(/ || $line =~ /$tag\s+\(/)
        {
            if($line =~ /#define/) # skip
            {
                next;
            }
            else
            {
                $line =~ s/[^,\(]+,[^,]+\);/ \"$file\", $lineno\);/;
                $line =~ s/\(\s+/\(/g;
            }

        }
    }
    return $line;
}


################################################################################################################
# set_macro_fname_lineno_of_files(@files)
################################################################################################################
sub set_macro_fname_lineno_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("set_macro_fname_lineno_of_files: handle file: %s\n", $file);
        &set_macro_fname_lineno_of_file($file);
    }
}

################################################################################################################
# set_macro_fname_lineno_of_file($file)
################################################################################################################
sub set_macro_fname_lineno_of_file
{
    my $file;

    my $fp;

    my $lines;
    my $line;

    my $line_num;
    my $line_idx;

    ($file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "set_macro_fname_lineno_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    open($fp,"> $file") || &com_die("err_write_file", "set_macro_fname_lineno_of_file: cannot open $file to write\n");
    #$fp = \*STDOUT;

    $line_num = scalar(@$lines);
    for($line_idx = 0; $line_idx < $line_num; )
    {
        $line = $$lines[ $line_idx ];
        $line_idx ++;

        chomp($line);
        $line = &set_macro_fname_lineno_of_line($file, $line_idx, $line);

        printf $fp ("%s\n", $line);
    }
    close($fp);
}

################################################################################################################
# set_macro_fname_lineno_of_line($file, $lineno, $line)
################################################################################################################
sub set_macro_fname_lineno_of_line
{
    my $file;
    my $lineno;

    my $line;

    my $tags;
    my $tag;

    ($file, $lineno, $line) = @_;

    $tags = [];

    &create_tag_table($tags);

    foreach $tag (@$tags)
    {
        if($line =~ /$tag\(/ || $line =~ /$tag\s+\(/)
        {
            if($line =~ /#define/)
            {
                $line = &set_macro_fname_lineno_of_define($tag, $line);
            }
            else
            {
                $line =~ s/\);/, \"$file\", $lineno\);/;
            }

        }
    }
    return $line;
}

################################################################################################################
# set_macro_fname_lineno_of_define($tag, $line)
################################################################################################################
sub set_macro_fname_lineno_of_define
{
    my $tag;
    my $line;

    my $chars;
    my $char;

    my $count;
    my $flag;

    ($tag, $line) = @_;

    if($line =~ /(#define\s+$tag)(.*)/)
    {
        $chars = [];
        @$chars = split(//, $2);

        $line = $1;
        $count = 0;
        $flag  = 1; # 1: match "(" and ")"
                    # 0: stop matching

        foreach $char (@$chars)
        {
            if($flag && $char eq "(")
            {
                $count ++;
            }

            if($flag && $char eq ")")
            {
                $count --;

                if(0 == $count)
                {
                    $line .= ", __fname__, __line__";
                    $flag = 0; # stop matching
                }
            }
            $line .= "$char";
        }
    }
    else
    {
        $line =~ s/\s+$//g;
        $line =~ s/\)$/, __fname__, __line__\)/;
    }


    return $line;
}

################################################################################################################
# create_tag_table(@tags)
################################################################################################################
sub create_tag_table
{
    my $tags;

    ($tags) = @_;


    push(@$tags, "alloc_static_mem");
    push(@$tags, "free_static_mem");

    push(@$tags, "SAFE_MALLOC");
    push(@$tags, "SAFE_FREE");
    push(@$tags, "SAFE_REALLOC");

    push(@$tags, "SAFE_CLIST_DATA_MALLOC");
    push(@$tags, "SAFE_CLIST_DATA_FREE");
    push(@$tags, "SAFE_CLIST_MALLOC");
    push(@$tags, "SAFE_CLIST_FREE");

    push(@$tags, "SAFE_CQUEUE_DATA_MALLOC");
    push(@$tags, "SAFE_CQUEUE_DATA_FREE");
    push(@$tags, "SAFE_CQUEUE_MALLOC");
    push(@$tags, "SAFE_CQUEUE_FREE");

    push(@$tags, "SAFE_CARRAY_DATA_MALLOC");
    push(@$tags, "SAFE_CARRAY_DATA_FREE");
    push(@$tags, "SAFE_CARRAY_MALLOC");
    push(@$tags, "SAFE_CARRAY_FREE");

    push(@$tags, "carray_new");
    push(@$tags, "carray_free");
    push(@$tags, "carray_init");

    push(@$tags, "SAFE_CSTACK_DATA_MALLOC");
    push(@$tags, "SAFE_CSTACK_DATA_FREE");
    push(@$tags, "SAFE_CSTACK_MALLOC");
    push(@$tags, "SAFE_CSTACK_FREE");

    push(@$tags, "SAFE_CSET_DATA_MALLOC");
    push(@$tags, "SAFE_CSET_DATA_FREE");
    push(@$tags, "SAFE_CSET_MALLOC");
    push(@$tags, "SAFE_CSET_FREE");

    push(@$tags, "SAFE_CVECTOR_DATA_MALLOC");
    push(@$tags, "SAFE_CVECTOR_DATA_FREE");
    push(@$tags, "SAFE_CVECTOR_MALLOC");
    push(@$tags, "SAFE_CVECTOR_FREE");

    push(@$tags, "cvector_new");
    push(@$tags, "cvector_free");
    push(@$tags, "cvector_init");
    push(@$tags, "cvector_clean");
    push(@$tags, "cvector_free_no_lock");
    push(@$tags, "cvector_clean_no_lock");

    push(@$tags, "SAFE_CINDEX_DATA_MALLOC");
    push(@$tags, "SAFE_CINDEX_DATA_FREE");
    push(@$tags, "SAFE_CINDEX_MALLOC");
    push(@$tags, "SAFE_CINDEX_FREE");

    push(@$tags, "cindex_new");
    push(@$tags, "cindex_free");
    push(@$tags, "cindex_init");
    push(@$tags, "cindex_clean");

    push(@$tags, "poly_f2n_alloc_bgn");
    push(@$tags, "poly_f2n_alloc_deg");
    push(@$tags, "poly_f2n_alloc_item");
    push(@$tags, "poly_f2n_alloc_poly");
    push(@$tags, "poly_f2n_free_bgn");
    push(@$tags, "poly_f2n_free_deg");
    push(@$tags, "poly_f2n_free_item");
    push(@$tags, "poly_f2n_free_poly");

    push(@$tags, "poly_z2_alloc_bgn");
    push(@$tags, "poly_z2_alloc_deg");
    push(@$tags, "poly_z2_alloc_item");
    push(@$tags, "poly_z2_alloc_poly");
    push(@$tags, "poly_z2_free_bgn");
    push(@$tags, "poly_z2_free_deg");
    push(@$tags, "poly_z2_free_item");
    push(@$tags, "poly_z2_free_poly");

    push(@$tags, "poly_zn_alloc_bgn");
    push(@$tags, "poly_zn_alloc_deg");
    push(@$tags, "poly_zn_alloc_item");
    push(@$tags, "poly_zn_alloc_poly");
    push(@$tags, "poly_zn_free_bgn");
    push(@$tags, "poly_zn_free_deg");
    push(@$tags, "poly_zn_free_item");
    push(@$tags, "poly_zn_free_poly");

    push(@$tags, "SAFE_TASKC_NODE_MALLOC");
    push(@$tags, "SAFE_TASKC_NODE_FREE");
    push(@$tags, "SAFE_TASKC_MGR_MALLOC");
    push(@$tags, "SAFE_TASKC_MGR_FREE");

    push(@$tags, "CLIST_LOCK");
    push(@$tags, "CLIST_UNLOCK");
    push(@$tags, "CLIST_CLEAN_LOCK");
    push(@$tags, "CLIST_INIT_LOCK");

    push(@$tags, "CARRAY_LOCK");
    push(@$tags, "CARRAY_UNLOCK");
    push(@$tags, "CARRAY_CLEAN_LOCK");
    push(@$tags, "CARRAY_INIT_LOCK");

    push(@$tags, "CVECTOR_LOCK");
    push(@$tags, "CVECTOR_UNLOCK");
    push(@$tags, "CVECTOR_CLEAN_LOCK");
    push(@$tags, "CVECTOR_INIT_LOCK");

    push(@$tags, "CINDEX_LOCK");
    push(@$tags, "CINDEX_UNLOCK");
    push(@$tags, "CINDEX_CLEAN_LOCK");
    push(@$tags, "CINDEX_INIT_LOCK");

    push(@$tags, "LOG_LOCK");
    push(@$tags, "LOG_UNLOCK");

    push(@$tags, "MAN_LOCK");
    push(@$tags, "MAN_UNLOCK");
    push(@$tags, "MAN_CLEAN_LOCK");
    push(@$tags, "MM_MGR_DEF");
    push(@$tags, "reg_mm_man");
    push(@$tags, "creg_static_mem_vec_add");

    push(@$tags, "TASKC_MD_LOCK");
    push(@$tags, "TASKC_MD_UNLOCK");

    push(@$tags, "cmutex_new");
    push(@$tags, "cmutex_init");
    push(@$tags, "cmutex_free");
    push(@$tags, "cmutex_clean");
    push(@$tags, "cmutex_lock");
    push(@$tags, "cmutex_unlock");
    push(@$tags, "ccond_new");
    push(@$tags, "ccond_init");
    push(@$tags, "ccond_free");
    push(@$tags, "ccond_clean");
    push(@$tags, "ccond_wait");
    push(@$tags, "ccond_reserve");
    push(@$tags, "ccond_release");
    push(@$tags, "ccond_release_all");
    push(@$tags, "ccond_spy");

    push(@$tags, "api_ui_malloc");
    push(@$tags, "api_ui_free");

    push(@$tags, "cstring_new");
    push(@$tags, "cstring_expand");

    push(@$tags, "TASK_MGR_CMUTEX_LOCK");
    push(@$tags, "TASK_MGR_CMUTEX_UNLOCK");

    push(@$tags, "task_node_alloc");
    push(@$tags, "task_req_alloc");
    push(@$tags, "task_rsp_alloc");
    push(@$tags, "task_any_alloc");
    push(@$tags, "task_rsp_free");

    push(@$tags, "TASK_MGR_COUNTER_INC_BY_TASK_REQ");
    push(@$tags, "TASK_MGR_COUNTER_DEC_BY_TASK_REQ");
    push(@$tags, "TASK_MGR_COUNTER_INC_BY_TASK_RSP");
    push(@$tags, "TASK_MGR_COUNTER_DEC_BY_TASK_RSP");

    push(@$tags, "TASK_BRD_SEQNO_CMUTEX_LOCK");
    push(@$tags, "TASK_BRD_SEQNO_CMUTEX_UNLOCK");

    push(@$tags, "CMISC_CMUTEX_INIT");
    push(@$tags, "CMISC_CMUTEX_LOCK");
    push(@$tags, "CMISC_CMUTEX_UNLOCK");
    push(@$tags, "cmisc_init");

    push(@$tags, "LOG_FILE_LOCK");
    push(@$tags, "LOG_FILE_UNLOCK");

    push(@$tags, "CSBUFF_INIT_LOCK");
    push(@$tags, "CSBUFF_CLEAN_LOCK");
    push(@$tags, "CSBUFF_LOCK");
    push(@$tags, "CSBUFF_UNLOCK");

    return;
}

################################################################################################################
# append_lost_line_of_files(@files)
################################################################################################################
sub append_lost_line_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("append_lost_line_of_files: handle file: %s\n", $file);
        &append_lost_line_of_file($file);
    }
}

################################################################################################################
# append_lost_line_of_file($file)
################################################################################################################
sub append_lost_line_of_file
{
    my $file;

    my $fp;

    my $lines;
    my $line;

    ($file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "append_lost_line_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    open($fp,"> $file") || &com_die("err_write_file", "append_lost_line_of_file: cannot open $file to write\n");
    #$fp = \*STDOUT;
    foreach $line (@$lines)
    {
        chomp($line);
        if($line =~ /^\},/)
        {
            printf $fp ("/*func para val   */     0, 0, {0},\n");
        }
        printf $fp ("%s\n", $line);
    }
    close($fp);
}


################################################################################################################
# dos2unix_of_files(@files)
################################################################################################################
sub dos2unix_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("dos2unix_of_files: handle file: %s\n", $file);
        &dos2unix_of_file($file);
    }
}

################################################################################################################
# dos2unix_of_file($file)
################################################################################################################
sub dos2unix_of_file
{
    my $file;

    ($file) = @_;

    &sys_cmd("dos2unix $file > /dev/null 2>&1", "on");
}

################################################################################################################
# discard_tail_space_of_files(@files)
################################################################################################################
sub discard_tail_space_of_files
{
    my $files;

    my $file;

    ($files) = @_;

    foreach $file (@$files)
    {
        printf STDOUT ("discard_tail_space_of_files: handle file: %s\n", $file);
        &discard_tail_space_of_file($file);
    }
}

################################################################################################################
# discard_tail_space_of_file($file)
################################################################################################################
sub discard_tail_space_of_file
{
    my $file;

    my $fp;

    my $lines;
    my $line;

    ($file) = @_;

    open($fp,"< $file") || &com_die("err_read_file", "discard_tail_space_of_file: cannot open $file to read\n");
    $lines = [];
    @$lines = <$fp>;
    close($fp);

    foreach $line (@$lines)
    {
        chomp($line);
        $line =~ s/\s+$//;
    }

    open($fp,"> $file") || &com_die("err_write_file", "discard_tail_space_of_file: cannot open $file to write\n");
    foreach $line (@$lines)
    {
        printf $fp ("%s\n", $line);
    }
    close($fp);
}

################################################################################################################
# collect_files_of_dir_list($dir_list, @postfixs, @files)
################################################################################################################
sub collect_files_of_dir_list
{
    my $dir_list;
    my $postfixs;
    my $files;

    my $dir_name_list;
    my $dir_name;

    ($dir_list, $postfixs, $files) = @_;

    $dir_name_list = [];
    @$dir_name_list = split(/[,:;]/, $dir_list);

    foreach $dir_name (@$dir_name_list)
    {
        if(! -r $dir_name)
        {
            &com_err("error:collect_files_of_dir: dir read access denied: %s\n", $dir_name);
            next;
        }

        printf STDOUT ("collect_files_of_dir_list: dir_name = %s\n", $dir_name);
        &collect_files_of_dir($dir_name, $postfixs, $files);
    }
    return;
}


################################################################################################################
# collect_files_of_dir($dir_name, @postfixs, @files)
################################################################################################################
sub collect_files_of_dir
{
    my $dir_name;
    my $postfixs;
    my $files;

    my $dir_fp;

    my $short_fname_list;
    my $short_fname;
    my $full_fname;

    ($dir_name, $postfixs, $files) = @_;

    #printf STDOUT ("collect_files_of_dir: dir_name = %s\n", $dir_name);

    if(! -r $dir_name)
    {
        &com_err("collect_files_of_dir: dir read access denied: %s\n", $dir_name);
        return;
    }

    opendir($dir_fp, "$dir_name") || &com_die("err_open_file", "collect_files_of_dir: collect_files_of_dir: cannot open dir $dir_name\n");
    $short_fname_list = [];
    @$short_fname_list = readdir($dir_fp);
    closedir($dir_fp);

    foreach $short_fname (@$short_fname_list)
    {
        #printf STDOUT ("collect_files_of_dir: handle file: %s\n", $short_fname);
        next if($short_fname eq "." || $short_fname eq "..");

        $full_fname = "$dir_name/$short_fname";

        if(-d $full_fname)
        {
            &collect_files_of_dir($full_fname, $postfixs, $files);
            next;
        }

        if(&check_postfix($short_fname, $postfixs) =~ /true/i )
        {
            #printf STDOUT ("push %s\n", $full_fname);
            push(@$files, $full_fname);
        }
    }
    return;
}

################################################################################################################
# check_postfix($file_name, @postfixs)
################################################################################################################
sub check_postfix
{
    my $file_name;
    my $postfixs;

    my $postfix;
    my $postfix_str;

    ($file_name, $postfixs) = @_;

    if(!defined($postfixs) || 0 == scalar(@$postfixs))
    {
        printf STDOUT ("[P] not defined or empty postfixs: @$postfixs\n");
        return "true"
    }

    foreach $postfix (@$postfixs)
    {
        $postfix_str = $postfix;
        $postfix_str =~ s/\./\\\./g;

        if($file_name =~ /$postfix_str$/)
        {
            #printf STDOUT ("[P]check: %s  <---> %s\n", $file_name, $postfix_str);
            return "true "
        }
        else
        {
            #printf STDOUT ("[F]check: %s  <---> %s\n", $file_name, $postfix_str);
        }
    }
    return "false";
}

################################################################################################################
# print_files($fp, @files)
################################################################################################################
sub print_files
{
    my $fp;
    my $files;

    my $file;

    ($fp, $files) = @_;

    foreach $file (@$files)
    {
        printf $fp ("%s\n", $file);
    }
}


################################################################################################################
# skip_comments($xml_line, $xml_fp)
#########parse_paras############################################################################################
sub skip_comments
{
    my $xml_line;
    my $xml_fp;

    ($xml_line, $xml_fp) = @_;

    # skip line comment
    if($xml_line =~ /<!--.*-->/)
    {
        return &skip_comment_line($xml_line);
    }

    # skip block comment
    if($xml_line =~ /<!--/)
    {
        return &skip_comment_block($xml_fp);
    }
    return $xml_line;
}

################################################################################################################
# skip_comment_block($xml_fp)
#########parse_paras############################################################################################
sub skip_comment_block
{
    my $xml_fp;

    my $xml_line;

    ($xml_fp) = @_;

    while(<$xml_fp>)
    {
        if($_ =~ /-->/)
        {
            $xml_line = $_;
            $xml_line =~ s/.*-->//g;
            return $xml_line;
        }
    }
}

################################################################################################################
# skip_comment_line($xml_line)
#########parse_paras############################################################################################
sub skip_comment_line
{
    my $xml_line;

    ($xml_line) = @_;

    $xml_line =~ s/<!--.*-->//g;

    return $xml_line;
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
            &com_err("error: absent parameter of $key\n");
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
    for( $arg_idx = 0; $arg_idx < $arg_num; $arg_idx ++ )
    {
        #&com_dbg(sprintf("arg %2d: %s\n", $arg_idx, $argv[ $arg_idx ]));

        if( $argv[ $arg_idx ] =~ /(.*?)=(.*)/ )
        {
            $$config{ $1 }  = $2;
            next;
        }
    }
}

################################################################################################################
# assert_dir_exist($dir_name)
################################################################################################################
sub assert_dir_exist
{
    my $dir_name;

    ($dir_name) = @_;

    if( ! defined( $dir_name ) )
    {
        &com_die("err_no_dir", "dir name is null");
    }

    if( ! -d $dir_name )
    {
        &com_die("err_no_dir", "not exist dir: ", $dir_name);
    }
}

################################################################################################################
# assert_file_exist($file_name)
################################################################################################################
sub assert_file_exist
{
    my $file_name;

    ($file_name) = @_;

    if( ! defined( $file_name ) )
    {
        &com_die("err_no_file", "file name is null");
    }

    if( ! -f $file_name )
    {
        &com_die("err_no_file", "not exist file: ", $file_name);
    }
}

################################################################################################################
# sys_cmd($cmd, $mode)
################################################################################################################
sub sys_cmd
{
    my $seq;
    my $cmd;
    my $mode;

    ( $cmd, $mode) = @_;

    &com_dbg("sys cmd: beg: $cmd\n") if ( (defined($verbose) && $verbose =~/on/i) && (!defined($mode) || $mode =~ /on/i) );
    #system($cmd);
    `$cmd`;
    &com_dbg("sys cmd: end: ok\n") if ( (defined($verbose) && $verbose =~/on/i) && (!defined($mode) || $mode =~ /on/i) );
}

################################################################################################################
# get_sys_cmd_result($cmd, $mode)
################################################################################################################
sub get_sys_cmd_result
{
    my $seq;
    my $cmd;
    my $mode;

    my $result;

    ( $cmd, $mode) = @_;

    &com_dbg("sys cmd: beg: $cmd\n") if ( (defined($verbose) && $verbose =~/on/i) && (!defined($mode) || $mode =~ /on/i) );
    #system($cmd);
    chomp($result = `$cmd`);
    &com_dbg("sys cmd: end: ok\n") if ( (defined($verbose) && $verbose =~/on/i) && (!defined($mode) || $mode =~ /on/i) );

    return $result;
}

################################################################################################################
# base_name($file_name)
################################################################################################################
sub base_name
{
    my $file_name;

    ($file_name) = @_;

    $file_name =~ s/.*\///g;

    return $file_name;
}

################################################################################################################
# dir_name($file_name)
################################################################################################################
sub dir_name
{
    my $file_name;

    ($file_name) = @_;

    $file_name =~ s/[^\/]+$//g;
    $file_name = "." if( $file_name eq "" );

    return $file_name;
}

################################################################################################################
# compose_space($level)
################################################################################################################
sub compose_space
{
    my $level;

    my $index;
    my $space;

    ($level) = @_;

    $space = "";
    for( $index = 0; $index < $level; $index ++ )
    {
        $space = "$space$g_tab";
    }

    return $space;
}

################################################################################################################
# open_log()
################################################################################################################
sub open_log
{
    my $log;
    my $fp;

    # read log file name from STDIN
    print STDOUT "pls input log file name(default STDOUT): ";
    $log = <STDIN>;
    chop($log);

    if( $log eq "" )
    {
        $fp = \*STDOUT;
    }
    else
    {
        open(LOG,"> $log") || &com_die("err_write_file", "cannot open log $log to write\n");
        $fp = \*LOG;
    }

    return $fp;
}

################################################################################################################
# close_log($fp)
################################################################################################################
sub close_log
{
    my $fp;

    ($fp) = @_;

    if( $fp != \*STDOUT && $fp != \*STDIN && $fp != \*STDERR )
    {
        close($fp);
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

################################################################################################################
# com_die($err_desc, @err_info)
################################################################################################################
sub com_die
{
    my $err_desc;
    my @err_info;

    my $err_code;

    ($err_desc, @err_info) = @_;

    if( $err_desc =~ /^\d+$/ )
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

################################################################################################################
# com_err($err_info)
################################################################################################################
sub com_err
{
    my $err_info;

    my $date;

    ($err_info) = @_;

    chomp($date = `date '+%m/%d/20%y %H:%M:%S'`);
    printf STDERR ("[%s] %s", $date, $err_info) if defined($err_info);
}

################################################################################################################
# com_dbg($info)
################################################################################################################
sub com_dbg
{
    my $info;

    my $date;

    ($info) = @_;

    chomp($date = `date '+%m/%d/20%y %H:%M:%S'`);
    printf STDOUT ("[%s] %s", $date, $info) if defined($info);
}

