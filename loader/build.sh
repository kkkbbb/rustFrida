#!/bin/bash

# 编译为对象文件
aarch64-linux-gnu-gcc -c -fPIC -nostdlib loader.c -o loader.o

# 提取.text段为二进制文件
aarch64-linux-gnu-objcopy -O binary -j .text loader.o loader.bin

# 清理临时文件
rm loader.o 