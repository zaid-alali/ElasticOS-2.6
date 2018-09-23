export CONCURRENCY_LEVEL=4

cd linux-2.6.38.8
cp /boot/config-$(uname -r) .config

fakeroot make-kpkg --initrd --append-to-version=-ehab kernel_image kernel_headers

cd ..
