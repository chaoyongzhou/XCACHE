From centos:6.9

#----------------------------------------------------------------------------------------------
# update yum source -- BEG
#----------------------------------------------------------------------------------------------
RUN cd /etc/yum.repos.d/ && rm -f *                                            \
    && curl -svo Centos-Base.repo http://mirrors.aliyun.com/repo/Centos-6.repo \
    && yum makecache && yum -y update
#----------------------------------------------------------------------------------------------
# update yum source -- END
#----------------------------------------------------------------------------------------------
#
#RUN echo 'export LC_ALL="en_US.UTF-8"' >> /etc/profile

# dependency packages
RUN yum -y install initscripts
# install crontabs
RUN yum -y install crontabs

# XCACHE installation
RUN curl -svo /home/xcache-5.7.5.5-R.x86_64.rpm http://www.test.com/rpm/xcache-5.7.5.5-R.x86_64.rpm -x 10.80.147.19:80
RUN rpm -ivh /home/xcache-5.7.5.5-R.x86_64.rpm

# RFS installation
RUN curl -svo /home/rfs-5.7.5.5-R.x86_64.rpm http://www.test.com/rpm/rfs-5.7.5.5-R.x86_64.rpm -x 10.80.147.19:80
RUN rpm -ivh /home/rfs-5.7.5.5-R.x86_64.rpm

# DETECT installation
RUN curl -svo /home/detect-5.7.5.5-R.x86_64.rpm http://www.test.com/rpm/detect-5.7.5.5-R.x86_64.rpm -x 10.80.147.19:80
RUN rpm -ivh /home/detect-5.7.5.5-R.x86_64.rpm

# P2P installation
#RUN curl -svo /home/p2p-2-5.7.5.5-R.x86_64.rpm http://www.test.com/rpm/p2p-2-5.7.5.5-R.x86_64.rpm -x 10.80.147.19:80
#RUN rpm -ivh /home/p2p-2-5.7.5.5-R.x86_64.rpm

# Bash Script
RUN curl -svo /home/xcache_run.sh http://www.test.com/rpm/xcache_run.sh -x 10.80.147.19:80

# netdata installation
#RUN curl -svo /home/kickstart-static64.sh  https://my-netdata.io/kickstart-static64.sh
#RUN bash /home/kickstart-static64.sh --accept --dont-wait --dont-start-it

# cleanup
RUN yum clean all && rm -f /home/*.rpm

#EXPOSE 80
#EXPOSE 19999

CMD bash /home/xcache_run.sh > /data/proclog/xcache_run.log 
