#!/bin/bash
set +	# enable/disable debug

REPO_PATH=$(pwd)
MODULE_PATH=$(pwd)/module
APP_PATH=$(pwd)/test-app
MODULE_NAME=virtual_tty.ko
CHECK_MODULE=$(lsmod | grep virtual_tty)

echo "Kernel module path is $MODULE_PATH"
echo "C++ application path is $APP_PATH"

echo "Installing linux headers..."
sudo apt-get install build-essential linux-headers-$(uname -r)
echo "linux headers instaled!"

echo "Installing picocom..."
sudo apt-get install picocom
echo "picocom instaled!"



echo "Check Makefiles..."

if [ -f "$MODULE_PATH/Makefile" ]; then
	echo "$MODULE_PATH/Makefile is exist"
	# read -n 1 -s -r -p "Press any key to continue..."
	echo "Building kernel module..."
	cd $MODULE_PATH
	echo "Kernel module has built successfully..."
	make clean
	make
else
	echo "Makefile is not exist for vtty kernel module"
	exit 1
fi

# if [ -f "$APP_PATH/Makefile" ]; then
# 	echo "$APP_PATH/Makefile is exist"
# 	read -n 1 -s -r -p "Press any key to continue..."
# 	echo "Building C++ test application..."
# 	cd $APP_PATH
# 	echo "C++ test application has built successfully..."
# 	#make clean
# 	#make
# else
# 	echo "Makefile is not exist for c++ test application"
# 	exit 1
# fi

if [[ "$CHECK_MODULE" == *"virtual_tty"* ]]; then
    echo "Module already exist, removing module ..."
    sudo rmmod -f $MODULE_NAME    
fi

cd $MODULE_PATH

echo "Inserting tty kernel module..."
sudo insmod $MODULE_NAME
echo "$MODULE_NAME inserted successfully"
sudo modinfo $MODULE_NAME


cd $REPO_PATH

sudo picocom -b 115200 -l -r /dev/vtty0