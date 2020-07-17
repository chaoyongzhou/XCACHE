%global __os_install_post %{nil}
Name: console 
Summary: DETECT - ORIGINAL SERVER DETECTING
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
%define service_dir /etc/systemd/system
%define docker_switch off

Source0: %{pkg_src}.tar.gz

AutoReqProv: no

#------------------------------------------------------------------------------------------
%description
Original Server Detecting

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

install_files=(
    %{pkg_src}/bin/console,0755,%{prefix}/bin/console
    %{pkg_src}/bin/config.xml,0644,%{prefix}/bin/config.xml
)

src_path=%{_topdir}/BUILD/
des_path=%{buildroot}/
for install_file in ${install_files[*]}
do
    install_file_name=$(echo ${install_file} | cut -d, -f1)
    install_file_mode=$(echo ${install_file} | cut -d, -f2)
    install_file_des=$(echo ${install_file} | cut -d, -f3)
    src_file_name=${src_path}/${install_file_name}
    des_file_name=${des_path}/${install_file_des}
    mkdir -vp $(dirname ${des_file_name}) || exit 1
    cp -af ${src_file_name} ${des_file_name} || exit 1
    chmod ${install_file_mode} ${des_file_name} || exit 1
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
#%config(noreplace) %{prefix}/bin/config.xml

#------------------------------------------------------------------------------------------
%changelog

