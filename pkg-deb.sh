#! /bin/sh

pkg=${1:-all}
verbose=${2:-off}
work_dir=$(pwd)
bgn_dir=bgn_ngx

make_pkg_xfs()
{
   local version
   local ret

   version=$1

   ln -s ${work_dir}/${bgn_dir}/build/xfs/debian/xfs-pkg-deb.sh .

   sh xfs-pkg-deb.sh xfs ${version} ${bgn_dir} no
   ret=$?

   [ ! -f xfs-pkg-deb.sh ] || rm -f xfs-pkg-deb.sh

   if [ $ret -ne 0 ]; then
       echo "error:make xfs pkg failed"
       exit 1
   fi
}

make_pkg_xcache()
{
   local version
   local ret

   version=$1

   if [ "${verbose}" == "off" ]; then
       ln -s ${work_dir}/${bgn_dir}/build/xcache/debian/xcache-pkg-deb.sh .
   else
       echo "[xcache] debug version"
       ln -s ${work_dir}/${bgn_dir}/build/xcache/debian/xcache-pkg-deb.debug.sh ./xcache-pkg-deb.sh
   fi

   sh xcache-pkg-deb.sh nginx ${version}
   ret=$?

   [ ! -f xcache-pkg-deb.sh ] || rm -f xcache-pkg-deb.sh

   if [ $ret -ne 0 ]; then
       echo "error:make xcache pkg failed"
       exit 1
   fi
}

make_pkg_detect()
{
   local version
   local ret

   version=$1

   ln -s ${work_dir}/${bgn_dir}/build/detect/debian/detect-pkg-deb.sh .

   sh detect-pkg-deb.sh detect ${version} ${bgn_dir} no
   ret=$?

   [ ! -f detect-pkg-deb.sh ] || rm -f detect-pkg-deb.sh

   if [ $ret -ne 0 ]; then
       echo "error:make detect pkg failed"
       exit 1
   fi
}

make_pkg_p2p()
{
   local version
   local network_level
   local ret

   version=$1
   network_level=$2

   ln -s ${work_dir}/${bgn_dir}/build/p2p/debian/p2p-pkg-deb.sh .

   sh p2p-pkg-deb.sh p2p ${version} ${network_level} ${bgn_dir} no
   ret=$?

   [ ! -f p2p-pkg-deb.sh ] || rm -f p2p-pkg-deb.sh

   if [ $ret -ne 0 ]; then
       echo "error:make p2p pkg failed"
       exit 1
   fi
}

make_pkg_tdns()
{
   local version
   local ret

   version=$1

   ln -s ${work_dir}/${bgn_dir}/build/tdns/debian/tdns-pkg-deb.sh .

   sh tdns-pkg-deb.sh tdns ${version} ${bgn_dir} no
   ret=$?

   [ ! -f tdns-pkg-deb.sh ] || rm -f tdns-pkg-deb.sh

   if [ $ret -ne 0 ]; then
       echo "error:make tdns pkg failed"
       exit 1
   fi
}

make_pkg_console()
{
   local version
   local ret

   version=$1

   ln -s ${work_dir}/${bgn_dir}/build/console/debian/console-pkg-deb.sh .

   sh console-pkg-deb.sh console ${version} ${bgn_dir} no
   ret=$?

   [ ! -f console-pkg-deb.sh ] || rm -f console-pkg-deb.sh

   if [ $ret -ne 0 ]; then
       echo "error:make console pkg failed"
       exit 1
   fi
}

if [ ! -f VERSION ]; then
    echo "error:not found file 'VERSION'"
    exit 1
fi

ver=$(cat VERSION)

echo "pkg: $pkg"
echo "ver: $ver"

if [ "$pkg" == "all" -o "$pkg" == "xfs" ]; then
    echo "=> xfs"
    make_pkg_xfs ${ver}
fi

if [ "$pkg" == "all" -o "$pkg" == "xcache" ]; then
    echo "=> xcache"
    make_pkg_xcache ${ver}
fi

#if [ "$pkg" == "all" -o "$pkg" == "detect" ]; then
#    echo "=> detect"
#    make_pkg_detect ${ver}
#fi

#if [ "$pkg" == "all" -o "$pkg" == "p2p" ]; then
#    echo "=> p2p"
#    make_pkg_p2p ${ver} 1  || exit 1 # L1 network
#    make_pkg_p2p ${ver} 2  || exit 2 # L2 network
#fi
#
#if [ "$pkg" == "all" -o "$pkg" == "tdns" ]; then
#    echo "=> tdns"
#    make_pkg_tdns ${ver}
#fi

if [ "$pkg" == "all" -o "$pkg" == "console" ]; then
    echo "=> console"
    make_pkg_console ${ver}
fi
