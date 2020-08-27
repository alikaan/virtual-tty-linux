# [Virtual TTY Linux Kernel Module Development]

## INFORMATION

Implement Linux kernel module providing virtual tty. 

* For each line the module will produce one line containing SHA256 hash.
* Example:
  * tty input: test
  * tty output: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

## SCRIPTS

* build.sh
    * Run this script to build virtual tty linux kernel module.

* load.sh
    * Run this script to load(insert) virtual tty linux kernel module. 
    * To check created virtual tty you can use `ls /dev | grep vtty`
    
* test.sh
    * Run this script to test virtual tty by using picocom serial port test tool.
    * When picocom is opened, input a series of chars and press enter. Vtty will sent you input value and its hashed output.

* unload.sh
    * Run this script to unload(remove) virtual tty linux kernel module.


* build_load_test.sh
    * Run this script to build,load and test virtual tty linux kernel module

## TEST MODULE

First Method

```shell
./build.sh
./load.sh
./test.sh
```
Second Method

```shell
./build_load_test.sh
```
## PICOCOM TEST LOG

```log
Welcome to virtual tty port!
Enter input, then press enter, you will see hashed output
To reset input values press '*'

input : abc
output : ba7816bf8f1cfea414140de5dae2223b0361a396177a9cb410ff61f2015ad
input : test
output : 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2bb822cd15d6c15b0f0a8
input : hello
output : 2cf24dba5fb0a3e26e83b2ac5b9e29e1b161e5c1fa7425e7343362938b9824
input : abc
output : ba7816bf8f1cfea414140de5dae2223b0361a396177a9cb410ff61f2015ad

```