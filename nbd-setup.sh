red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

ping -c 1 $EOS_REMOTE_MACHINE 

if [ $? -ne 0 ]
	then
		echo ${red} "$EOS_REMOTE_MACHINE is unreachable!..." ${reset}
		exit 1
fi

ssh -t -t root@$EOS_REMOTE_MACHINE << HERE
	cd $(EOS_DIR)/misc/nbd-2.9.16/
	./nbd-server 1043 /mnt/nbdserv &
	sysctl vm.page-cluster=0
	exit
HERE

sysctl vm.page-cluster=0

cd ./misc/nbd-2.9.16/
sudo ./nbd-server 1043 /mnt/nbdserv &
cd ../../

cd ./misc/get_put_pg_impl/
insmod ./gppi.ko

cd ../eos-nbd/nbd-kmod/
insmod ./eosnbd.ko

cd ../eos-pager/dist/Debug/GNU-Linux-x86/

sleep 0.5

./eos-pager $EOS_REMOTE_MACHINE 1043 /dev/eosnbd1
mkswap -f /dev/eosnbd1
swapon /dev/eosnbd1

ssh -t -t root@$EOS_REMOTE_MACHINE << HERE
	cd $(EOS_DIR)/misc/get_put_pg_impl
	insmod ./gppi.ko
	cd $(EOS_DIR)/misc/eos-nbd/nbd-kmod/ 
	insmod ./eosnbd.ko 
	cd ../eos-pager/dist/Debug/GNU-Linux-x86/ 
	./eos-pager \$EOS_REMOTE_MACHINE 1043 /dev/eosnbd1 
	mkswap -f /dev/eosnbd1 
	swapon /dev/eosnbd1
	exit
HERE

