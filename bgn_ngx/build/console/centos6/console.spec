%global __os_install_post %{nil}
Name: console 
Summary: CONSOLE - console utility 
Version: %{version}
Release: R
Vendor: chaoyong.zhou / bgnvendor@163.com
License: TBD
Group: bgnvendor@163.com
BuildRoot: %{_topdir}/BUILDROOT
Prefix: /usr/local/%{name}
BuildRequires:  gcc,make
Requires: pcre,expat,libxml2

%define pkg_src %{name}-%{version}

Source0: %{pkg_src}.tar.gz

AutoReqProv: no

#------------------------------------------------------------------------------------------
%description
Console Utility

#------------------------------------------------------------------------------------------
%prep

#------------------------------------------------------------------------------------------
%setup -q

#------------------------------------------------------------------------------------------
%build
#autoreconf -f -i
#CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{prefix} --localstatedir=/var/
#make %{?_smp_mflags}

sh make_console.sh console > /dev/null

#------------------------------------------------------------------------------------------
%install
#make install DESTDIR=%{buildroot}
# ---- console binary files -------
bin_files=(
    console,0755 
    config.xml,0644
)
src_path=%{_topdir}/BUILD/%{pkg_src}/bin
des_path=%{buildroot}/%{prefix}/bin
mkdir -vp ${des_path}
for bin_file in ${bin_files[*]}
do
    bin_file_name=$(echo ${bin_file} | cut -d, -f1)
    bin_file_mode=$(echo ${bin_file} | cut -d, -f2)
    src_file_name=${src_path}/${bin_file_name}
    des_file_name=${des_path}/${bin_file_name}
    cp -af ${src_file_name} ${des_path} && chmod ${bin_file_mode} ${des_file_name}
done

# ---- console dependency ----
src_path=%{_topdir}/BUILDROOT%{prefix}/depend
des_path=%{buildroot}%{prefix}/depend
mkdir -vp ${des_path}
cp -af ${src_path}/* ${des_path} || exit 1

# ---- console log directory ----
mkdir -vp %{buildroot}/data/proclog/log/console

#------------------------------------------------------------------------------------------
%clean

#------------------------------------------------------------------------------------------
%pre

#------------------------------------------------------------------------------------------
%post

#------------------------------------------------------------------------------------------
%preun

#------------------------------------------------------------------------------------------
%postun

#------------------------------------------------------------------------------------------
%files
%defattr  (-,root,root,0755)
%{prefix}/bin
%{prefix}/depend
/data/proclog/log/console
%defattr  (-,nobody,nobody,0755)
%config(noreplace) %{prefix}/bin/config.xml

#------------------------------------------------------------------------------------------
%changelog

