#!/bin/bash
sudo sysctl vm.overcommit_memory=2
sudo sysctl vm.swappiness=100
cd ./misc/start-migrate-impl
interface="$(ifconfig | grep $EOS_LOCAL_ADDRESS -B 1 | head -n1 |awk '{split($0, a," ");print a[1]}')"
sudo insmod ./smi.ko
cd ../

cd kmod-bcast-sender/
sudo insmod ./bcastsender.ko
cd ../
cd setup-bcast-sender/
./dist/Debug/GNU-Linux-x86/setup-bcast-sender $interface 9097 &

cd ../
cd kmod-bcast-listener/
sudo insmod ./bcastlistener.ko
cd ../
cd setup-bcast-listener/
./dist/Debug/GNU-Linux-x86/setup-bcast-listener $interface 9097 &

cd ../

# This is just to consume some PIDs.
# Ubuntu hides ns_namespace_pid :(
for i in 'seq 1 500'
do
	./empty	 &
done

cd ../
pwd
./$1 &
pid=$!


cd ./misc/setup-migration-socket/

cd ../..
cd ./misc/migrate/

cd ..
cd ./pages_server/

sudo insmod ./pages_server.ko 
cd ../../

cd ./rstrt_src_kmod/

sudo insmod ./rstrt_src.ko pid=$$ remote=$EOS_REMOTE_MACHINE remote_ps_port=$EOS_REMOTE_PS_PORT rs_port=$EOS_RESTART_LISTENER_PORT
cd ../

cd ./chkpt_dest_kmod

sudo insmod ./chckpt_dest.ko port=9999 remote=$EOS_REMOTE_MACHINE remote_ps_port=8022 
cd ..
echo migrating $pid
sleep 0.5
sudo ./misc/migrate/dist/Debug/GNU-Linux-x86/migrate $pid 1
#cd ../../../..
cd ./misc/mark_elastic/
sudo insmod ./testproc.ko pid=$pid
cd ../../


