###############################################################################
#
#   Copyright (C) Chaoyong Zhou
#   Email: bgnvendor@163.com
#   QQ: 2796796
#
################################################################################

pkgname=('console')
pkgver=${version}
pkgrel=0
arch=('x86_64')
groups=('hansoul')
url='https://github.com/chaoyongzhou/XCACHE'
license=('custom')
pkgdesc="BGN Console Utility"

docker_switch=off

prefix=/usr/local/${pkgname}
pkg_src=${pkgname}-${pkgver}

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
    console,0755
    config.xml,0644
)

#prepare() {
#}

build() {
    echo "[DEBUG] build beg ---------------------------------------------------------"
    cp -rp ${srcdir}/../${pkgname}-${pkgver} ${srcdir}/
    cd "$srcdir/$pkgname-$pkgver"
    sh make_console.sh console > /dev/null
    echo "[DEBUG] build end ---------------------------------------------------------"
}

package() {
    echo "[DEBUG] package ---------------------------------------------------------"
    echo "[DEBUG] package: pkgdir  : ${pkgdir}"
    echo "[DEBUG] package: srcdir  : ${srcdir}"
    echo "[DEBUG] package: startdir: ${startdir}"
    
    #make install DESTDIR=${pkgdir}
    # ---- console binary files -------
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

    # ---- console dependency ----
    src_path=${startdir}${prefix}/depend
    des_path=${pkgdir}${prefix}/depend
    mkdir -vp ${des_path}
    cp -af ${src_path}/* ${des_path} || exit 1
}
