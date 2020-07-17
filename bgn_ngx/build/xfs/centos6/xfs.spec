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
bin_files=(
    xfs,0755 
    xfs_tool,0755
    xfs_init.sh,0755 
    ss_state.sh,0755 
    ss_peer.sh,0755 
    config.xml,0644
    mkdsk.sh,0755
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

# ---- xfs service files -------
service_files=(
    xfs_service,0755,xfs
)
src_path=%{_topdir}/BUILD/%{pkg_src}/bin
des_path=%{buildroot}/etc/init.d
mkdir -vp ${des_path}
for service_file in ${service_files[*]}
do
    service_file_name=$(echo ${service_file} | cut -d, -f1)
    service_file_mode=$(echo ${service_file} | cut -d, -f2)
    service_file_des=$(echo ${service_file} | cut -d, -f3)
    src_file_name=${src_path}/${service_file_name}
    des_file_name=${des_path}/${service_file_des}
    cp -af ${src_file_name} ${des_file_name} && chmod ${service_file_mode} ${des_file_name} 
done

# ---- xfs crontab files ----
crontab_files=(
    xfs_crontab,0644,xfs
)
src_path=%{_topdir}/BUILD/%{pkg_src}/bin
des_path=%{buildroot}/etc/cron.d
mkdir -vp ${des_path}
for crontab_file in ${crontab_files[*]}
do
    crontab_file_name=$(echo ${crontab_file} | cut -d, -f1)
    crontab_file_mode=$(echo ${crontab_file} | cut -d, -f2)
    crontab_file_des=$(echo ${crontab_file} | cut -d, -f3)
    src_file_name=${src_path}/${crontab_file_name}
    des_file_name=${des_path}/${crontab_file_des}
    cp -af ${src_file_name} ${des_file_name} && chmod ${crontab_file_mode} ${des_file_name} 
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

service_files=(
    xfs_service,0755,xfs
)
for service_file in ${service_files[*]}
do
    service_file_des=$(echo ${service_file} | cut -d, -f3)

    chkconfig --add ${service_file_des}

    if [ "%{docker_switch}" != "on" ]; then
        echo '[POST] start ' ${service_file_des} ' ... '
        service  ${service_file_des} start
        echo '[POST] start ' ${service_file_des} ' done '
    
        echo '[POST] check ' ${service_file_des} ' status '
        service  ${service_file_des} status
    fi
done

# ---- crontab ----
echo '[POST] restart crond'
service crond restart

#------------------------------------------------------------------------------------------
%preun
service_files=(
    xfs_service,0755,xfs
)
for service_file in ${service_files[*]}
do
    service_file_des=$(echo ${service_file} | cut -d, -f3)

    echo '[POST] stop ' ${service_file_des} ' ... '
    service  ${service_file_des} stop
    echo '[POST] stop ' ${service_file_des} ' done '

    echo '[POST] check ' ${service_file_des} ' status '
    service  ${service_file_des} status

    service_file_des=$(echo ${service_file} | cut -d, -f3)
    chkconfig --del ${service_file_des}
done

#------------------------------------------------------------------------------------------
%postun
echo '[POST] restart crond'
service crond restart

#------------------------------------------------------------------------------------------
%files
%defattr  (-,root,root,0755)
%{prefix}/bin
%{prefix}/depend
/data/proclog/log/xfs
/etc/init.d/xfs
/etc/cron.d/xfs
%defattr  (-,nobody,nobody,0755)
#%config(noreplace) %{prefix}/etc/config.xml

#------------------------------------------------------------------------------------------
%changelog

