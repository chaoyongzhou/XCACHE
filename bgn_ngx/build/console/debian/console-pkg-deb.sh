#! /bin/bash -x

fs_type=${1:-console}
version=${2:-5.7.5.0}
pkg_name=${fs_type}-${version}
pkg_src=${3:-${pkg_name}}

need_confirm=${4:-yes}

echo -e "\nCommand: \n\t\033[0;34m$0 <console> <version> <src path>\033[0m\t\tdefault version is ${version}"

if [ "$need_confirm" = "yes" ]; then
    echo -ne "\nBuild \033[0;32m${pkg_name} from ${pkg_src}\033[0m (y/N) "
    read answer
    
    if [ "$answer" != "y" ]; then
        exit -1;
    fi
fi

CUR_DIR=$(pwd)
PKGBUILD_DIR=${CUR_DIR}/pkgbuild
DEPEND_DIR=/usr/local/${fs_type}/depend

# remove old packages
rm -f ${fs_type}_${version}_*.deb
rm -f ${fs_type}-dbgsym_${version}_amd64.deb
rm -f ${fs_type}_${version}.tar.gz
rm -f ${fs_type}_${version}_amd64.buildinfo
rm -f ${fs_type}_${version}_amd64.changes

rm -rf ${PKGBUILD_DIR}
#mkdir -vp ${PKGBUILD_DIR}/src
mkdir -vp ${PKGBUILD_DIR}/build

BUILD_ROOT=${PKGBUILD_DIR}/build

# prepare makefile
mkdir -vp $BUILD_ROOT/${fs_type}-${version}
cp -af ${CUR_DIR}/${pkg_src}/*   $BUILD_ROOT/${fs_type}-${version}
cd $BUILD_ROOT/${fs_type}-${version}/
mv -f Makefile.${fs_type} Makefile

DEBIAN_ROOT=${BUILD_ROOT}/${fs_type}-${version}/debian

# debian files
mkdir -vp $DEBIAN_ROOT
cp -pr build/${fs_type}/debian/debian/* ${DEBIAN_ROOT}/
cp -p ${BUILD_ROOT}/${fs_type}-${version}/COPYING ${DEBIAN_ROOT}/copyright

# build package
sed -i "s@\$version@$version@" $DEBIAN_ROOT/changelog
sed -i "s@\$date@$(date -R)@" $DEBIAN_ROOT/changelog
cd $DEBIAN_ROOT/..
dpkg-buildpackage -jauto --no-sign > /dev/null || exit 1

# move deb
cd ${BUILD_ROOT}
mv -f ${fs_type}_${version}_amd64.deb ${CUR_DIR}/
mv -f ${fs_type}-dbgsym_${version}_amd64.deb ${CUR_DIR}/
mv -f ${fs_type}_${version}.tar.gz ${CUR_DIR}/
mv -f ${fs_type}_${version}_amd64.buildinfo ${CUR_DIR}/
mv -f ${fs_type}_${version}_amd64.changes ${CUR_DIR}/

# clean up
rm -rf ${PKGBUILD_DIR}
