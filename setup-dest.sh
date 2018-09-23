echo $$
interface="$(ifconfig | grep $EOS_LOCAL_ADDRESS -B 1 | head -n1 |awk '{split($0, a," ");print a[1]}')"
cd ./misc/
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

cd ../../

cd ./rstrt_src_kmod/
sudo insmod ./rstrt_src.ko pid=$$ remote=$EOS_REMOTE_MACHINE remote_ps_port=$EOS_REMOTE_PS_PORT rs_port=$EOS_RESTART_LISTENER_PORT
cd ../

cd ./misc/start-migrate-impl
sudo insmod ./smi.ko
cd ../../

$SHELL
