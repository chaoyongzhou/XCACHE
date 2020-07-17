#!/bin/bash

fs_type=${1:-xfs}
version=${2:-5.7.5.0}
pkg_name=${fs_type}-${version}
pkg_src=${3:-${pkg_name}}

need_confirm=${4:-yes}

os_type=c7

echo -e "\nCommand: \n\t\033[0;34m$0 <xfs> <version> <src path>\033[0m\t\tdefault version is ${version}"

if [ "$need_confirm" == "yes" ]; then
    echo -ne "\nBuild \033[0;32m${pkg_name} from ${pkg_src}\033[0m (y/N) "
    read answer
    
    if [ "$answer" != "y" ]; then
        exit -1;
    fi
fi

CUR_DIR=$(pwd)
BUILD_DIR=${CUR_DIR}/rpmbuild
DEPEND_DIR=/usr/local/${fs_type}/depend
SOURCES=${BUILD_DIR}/SOURCES/
BUILDROOT=${BUILD_DIR}/BUILDROOT/

# remove old rpms
rm -f xfs-*.rpm

rm -rf ${BUILD_DIR}
echo "%_topdir ${BUILD_DIR}" > ~/.rpmmacros
mkdir -vp ${BUILD_DIR}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# prepare makefile
rm -f ${CUR_DIR}/${fs_type}.${os_type}.spec
cp -af ${pkg_src}/build/${fs_type}/centos7/${fs_type}.${os_type}.spec       ${CUR_DIR}/${fs_type}.${os_type}.spec || exit 1

mkdir -vp $SOURCES/${fs_type}-${version}
cp -af ${CUR_DIR}/${pkg_src}/*      $SOURCES/${fs_type}-${version}
cp -af ${CUR_DIR}/${fs_type}.${os_type}.spec   $SOURCES/

# replace files
mkdir -vp $BUILDROOT/${DEPEND_DIR}
cp -af ${DEPEND_DIR}/* $BUILDROOT/${DEPEND_DIR}  || exit 1

sed -i "s@^Version:.*@Version: $version@" $SOURCES/${fs_type}.${os_type}.spec

cd $SOURCES && tar zcvf ${fs_type}-${version}.tar.gz ${fs_type}-${version}

QA_RPATHS=0x0013 rpmbuild -bb ${fs_type}.${os_type}.spec && mv $BUILD_DIR/RPMS/x86_64/*.rpm $CUR_DIR

# clean up
rm -rf ${BUILD_DIR}
rm -rf ${CUR_DIR}/${fs_type}.${os_type}.spec
