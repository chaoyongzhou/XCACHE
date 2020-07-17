###############################################################################
#
#   Copyright (C) Chaoyong Zhou
#   Email: bgnvendor@163.com
#   QQ: 2796796
#
################################################################################

#pkgbase=xfs
pkgname=('xfs')
pkgver=${version}
pkgrel=0
arch=('x86_64')
groups=('hansoul')
url='https://github.com/chaoyongzhou/XCACHE'
license=('custom')
pkgdesc="Randome Access File System (Raw Disk Version)"

docker_switch=off

prefix=/usr/local/${pkgname}
pkg_src=${pkgname}-${pkgver}

install=${pkgname}.pkg.install

source=()

md5sums=()

makedepends=()

options=(
    'strip'
    'staticlibs'
    '!docs'
    'debug'
    'makeflags'
    'emptydirs'
)

bin_files=(
    xfs,0755
    xfs_tool,0755
    xfs_init.sh,0755
    ss_state.sh,0755
    ss_peer.sh,0755
    config.xml,0644
    mkdsk.sh,0755
)

systemd_service_files=(
    xfs.pkg.service,0644,xfs.pkg.service
)

service_files=(
    xfs.pkg.cli,0755,xfs
)

crontab_files=(
    xfs_crontab,0644,xfs
)
#prepare() {
#}

build() {
    echo "[DEBUG] build beg ---------------------------------------------------------"
    echo "[DEBUG] build: pwd: $(pwd)"
    echo "[DEBUG] build: startdir: $startdir"
    echo "[DEBUG] build: pkgdir  : $pkgdir"
    echo "[DEBUG] build: srcdir  : $srcdir"
    echo "[DEBUG] $srcdir/$pkgname-$pkgver"
    echo "[DEBUG] cp -rp ${srcdir}/../${pkgname}-${pkgver} ${srcdir}/"
    cp -rp ${srcdir}/../${pkgname}-${pkgver} ${srcdir}/
    cd "$srcdir/$pkgname-$pkgver"
    sh make_xfs.sh xfs > /dev/null
    echo "[DEBUG] build end ---------------------------------------------------------"
}

package() {
    echo "[DEBUG] package ---------------------------------------------------------"
    echo "[DEBUG] package: pkgdir  : ${pkgdir}"
    echo "[DEBUG] package: srcdir  : ${srcdir}"
    echo "[DEBUG] package: startdir: ${startdir}"
    
    #make install DESTDIR=${pkgdir}
    # ---- xfs binary files -------
    src_path=${srcdir}/${pkg_src}/bin
    des_path=${pkgdir}${prefix}/bin
    mkdir -vp ${des_path}
    for bin_file in ${bin_files[*]}
    do
        bin_file_name=$(echo ${bin_file} | cut -d, -f1)
        bin_file_mode=$(echo ${bin_file} | cut -d, -f2)
        src_file_name=${src_path}/${bin_file_name}
        des_file_name=${des_path}/${bin_file_name}
        cp -af ${src_file_name} ${des_path} && chmod ${bin_file_mode} ${des_file_name}
        echo "[DEBUG] bin file: cp -af ${src_file_name} ${des_path}"
    done

    # ---- xfs systemd service files ----
    src_path=${srcdir}/${pkg_src}/bin
    des_path=${pkgdir}/etc/systemd/system
    mkdir -vp ${des_path}
    for service_file in ${systemd_service_files[*]}
    do
        service_file_name=$(echo ${service_file} | cut -d, -f1)
        service_file_mode=$(echo ${service_file} | cut -d, -f2)
        service_file_des=$(echo ${service_file} | cut -d, -f3)
        src_file_name=${src_path}/${service_file_name}
        des_file_name=${des_path}/${service_file_des}
        cp -af ${src_file_name} ${des_file_name} && chmod ${service_file_mode} ${des_file_name} 
        echo "[DEBUG] systemd service file: cp -af ${src_file_name} ${des_file_name}"
    done

    # ---- xfs service files ----
    src_path=${srcdir}/${pkg_src}/bin
    des_path=${pkgdir}/etc/init.d
    mkdir -vp ${des_path}
    for service_file in ${service_files[*]}
    do
        service_file_name=$(echo ${service_file} | cut -d, -f1)
        service_file_mode=$(echo ${service_file} | cut -d, -f2)
        service_file_des=$(echo ${service_file} | cut -d, -f3)
        src_file_name=${src_path}/${service_file_name}
        des_file_name=${des_path}/${service_file_des}
        cp -af ${src_file_name} ${des_file_name} && chmod ${service_file_mode} ${des_file_name} 
        echo "[DEBUG] service file: cp -af ${src_file_name} ${des_file_name}"
    done

    # ---- xfs crontab files ----
    src_path=${srcdir}/${pkg_src}/bin
    des_path=${pkgdir}/etc/cron.d
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
    src_path=${startdir}${prefix}/depend
    des_path=${pkgdir}${prefix}/depend
    mkdir -vp ${des_path}
    cp -af ${src_path}/* ${des_path} || exit 1

    # ---- xfs log directory ----
    mkdir -vp ${pkgdir}/data/proclog/log/xfs
}
