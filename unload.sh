#!/bin/bash
set +x	# enable/disable debug

REPO_PATH=$(pwd)
MODULE_PATH=$(pwd)/module
MODULE_NAME=virtual_tty.ko
CHECK_MODULE=$(lsmod | grep virtual_tty)

echo $CHECK_MODULE

if [[ "$CHECK_MODULE" == *"virtual_tty"* ]]; then
    echo "module allready exist, removing module ..."
    sudo rmmod -f $MODULE_NAME    
fi
