#!/bin/bash
set -e  # 如果某个命令失败，则立即退出

# 1. 进入 compiler 目录并编译 my-clang
echo "Building compiler/my-clang..."
cd compiler
make clean all
cd ..

# 2. 进入 lib 目录并编译 libio.so、liblog.so、MyPass.so
echo "Building lib libraries..."
cd lib
make clean all
cd ..

# 3. 使用自定义 clang 编译 demo
echo "Building demo (main)..."
make clean all
