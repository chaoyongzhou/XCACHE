%global __os_install_post %{nil}
Name: xfs 
Summary: XFS - Random Access File System (Raw Disk Version)
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
Random Access File System

#------------------------------------------------------------------------------------------
%prep

#------------------------------------------------------------------------------------------
%setup -q

#------------------------------------------------------------------------------------------
%build
#autoreconf -f -i
#CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{prefix} --localstatedir=/var/
#make %{?_smp_mflags}

sh make_xfs.sh xfs > /dev/null

#------------------------------------------------------------------------------------------
%install
#make install DESTDIR=%{buildroot}
# ---- xfs binary files -------
install_files=(
    %{pkg_src}/bin/xfs,0755,%{prefix}/bin/xfs
    %{pkg_src}/bin/xfs_tool,0755,%{prefix}/bin/xfs_tool
    %{pkg_src}/bin/config.xml,0644,%{prefix}/bin/config.xml
    %{pkg_src}/build/xfs/centos7/xfs.c7.init.sh,0755,%{prefix}/bin/xfs_init.sh
    %{pkg_src}/build/xfs/centos7/xfs.c7.service,0644,/etc/systemd/system/xfs.c7.service.default
    %{pkg_src}/build/xfs/centos7/xfs.c7.cli,0755,/etc/init.d/xfs
    %{pkg_src}/build/xfs/centos7/xfs_crontab,0644,/etc/cron.d/xfs
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

# ---- xfs dependency ----
src_path=%{_topdir}/BUILDROOT%{prefix}/depend
des_path=%{buildroot}%{prefix}/depend
mkdir -vp ${des_path}
cp -af ${src_path}/* ${des_path} || exit 1

# ---- xfs log directory ----
mkdir -vp %{buildroot}/data/proclog/log/xfs

#------------------------------------------------------------------------------------------
%clean

#------------------------------------------------------------------------------------------
%pre

#------------------------------------------------------------------------------------------
%post
echo -n '[POST] init xfs ...................... '
if [ "%{docker_switch}" == "on" ]; then
    chmod 0755 %{prefix}/bin/xfs_init.sh
else
    bash %{prefix}/bin/xfs_init.sh > /data/proclog/log/xfs/xfs_init.log 2>&1
fi

echo 'done'

# reload due to service changed
systemctl daemon-reload

for service_file in $(ls -1p %{service_dir}/xfs*.service)
do
    service_file_des=$(basename ${service_file})

    systemctl enable ${service_file_des}

    if [ "%{docker_switch}" != "on" ]; then
        echo '[POST] start ' ${service_file_des} ' ... '
        systemctl start ${service_file_des}
        echo '[POST] start ' ${service_file_des} ' done '

        echo '[POST] check ' ${service_file_des} ' status '
        systemctl status ${service_file_des}
    fi
done

# ---- crontab ----
echo '[POST] restart crond'
systemctl restart crond

#------------------------------------------------------------------------------------------
%preun
for service_file in $(ls -1p %{service_dir}/xfs*.service)
do
    service_file_des=$(basename ${service_file})

    echo '[POST] stop ' ${service_file_des} ' ... '
    systemctl stop ${service_file_des}
    echo '[POST] stop ' ${service_file_des} ' done '

    echo '[POST] check ' ${service_file_des} ' status '
    systemctl status ${service_file_des}

    service_file_des=$(echo ${service_file_des} | cut -d, -f3)
    systemctl disable ${service_file_des}
done
#------------------------------------------------------------------------------------------
%postun
rm -f %{service_dir}/xfs*.service
# reload due to service changed
systemctl daemon-reload

# ---- crontab ----
echo '[POST] restart crond'
systemctl restart crond

#------------------------------------------------------------------------------------------
%files
%defattr  (-,root,root,0755)
%{prefix}/bin
%{prefix}/depend
/data/proclog/log/xfs
/etc/init.d/xfs
/etc/cron.d/xfs
%{service_dir}/xfs.c7.service.default
%defattr  (-,nobody,nobody,0755)
#%config(noreplace) %{prefix}/etc/config.xml

#------------------------------------------------------------------------------------------
%changelog

