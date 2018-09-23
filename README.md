---
title: ElasticOS
---

About
=====

ElasticOS is a Linux OS with a set of operating system primitives which provides a scaling abstraction to cloud applications in which they can transparently be enabled to support scaled execution across multiple physical nodes as resource needs go beyond that available on a single machine.

These primitives include:

-   Stretch: extend the address space of an application to a new node.

-   Push and Pull: to move pages between nodes as needed for execution and optimization.

-   Jump: to transfer execution in a very lightweight manner between nodes.

 

This joint disaggregation of memory and computing allows for transparent elasticity, improving an application’s performance by capitalizing on the underlying dynamic infrastructure without needing an application re-write. We have implemented these primitives in a Linux 2.6.

 

For more details please see:

[Elasticizing Linux via Joint Disaggregation of Memory and Computation](https://arxiv.org/pdf/1806.00885.pdf)

 

How to Use ElasticOS
====================

Prerequisites :
---------------

-   To run ElasticOS you will need two physical machines (x86-64), with 1Gb Ethernet connection, and at least 2GB RAM.

-   Both machines should have Linux 2.x installed. (Linux 2.6.38 is recommended)

-   Both machines must have ssh public key authentication enabled, and keys copied to both machines.

 

Setup:
------

### 1. Clone ElasticOS source code.

$$
cd ~
$$

$$
git clone 
$$

### 2. Install prerequisites to compile and install new kernel.

$$
cd ~/ElasticOS-2.6/
$$

$$
./prereq.sh    #(reqiures root privelage)
$$

### 3. Compile and install new kernel.

$$
cd linux-2.6.38.8/
$$

$$
cp /boot/config-$(uname -r) .config
$$

Customize kernel (Optional,recommended):

$$
make menuconfig  #follow menu configuration to customize kernel name, save and exit
$$

$$
./compile.sh
$$

$$
cd ../
$$

$$
sudo dpkg -i linux-image-2.6.38.8-(your kernel custom name).deb
$$

$$
sudo dpkg -i linux-headers-2.6.38.8-(your kernel custom name).debsudo reboot
$$

$$
sudo reboot
$$

### 4. Configure both machines.

Make sure to setup both machines with static IP addresses.

setup environment variables by modifying the file “/etc/environment” (requires root privilege), add the following variables, save and exit:

$$
EOS_REMOTE_PS_PORT=8022
$$

$$
EOS_RESTART_LISTENER_PORT=9999
$$

$$
EOS_REMOTE_MACHINE= (other machines IPv4 address)
EOS_LOCAL_ADDRESS= (local IPv4 static address)
$$

$$
sudo reboot
$$

Running Tests:
--------------

 

place you test application in ElasticOS home directory “\~/ElasticOS-2.6”, and make sure to have an exact copy of the binary file on both machines.

On machine1:

$$
cd ~/ElasticOS-2.6/
$$

$$
./nbd-setup.sh
$$

$$
./setup-dest.sh  #prepare first machine to allow stretch 
$$

On machine2:

$$
cd ~/ElasticOS-2.6/
$$

$$
./setup-src.sh “executable file name” 
$$

machine2 will start your application, and when it runs out of resources, it will use remote resources from machine1.

running setup-dest.sh and setup-src.sh scripts must be done with minimum delay between the two, and in the same order mentioned above.

 

Important Notes:
----------------

-   ElasticOS is still under development , and can run only single threaded applications, and does not support files or IO.

-   ElasticOS was tested on the following algorithms, implemented in C/C++, with memory foot print of \~16GB:

    -   Depth First Search.

    -   Linear Search.

    -   Heap Sort.

    -   Block Sort.

    -   Dijkstra’s Shortest Path.

 
