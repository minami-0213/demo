#!/bin/bash
set -e  # 如果某个命令失败，则立即退出

# 1. 进入 compiler 目录并清理 my-clang
echo "Cleaning compiler/my-clang..."
cd compiler
make clean
cd ..

# 2. 进入 lib 目录并清理 libio.so、liblog.so、MyPass.so
echo "Cleaning lib libraries..."
cd lib
make clean
cd ..

# 3. 使用自定义 clang 清理 demo
echo "Cleaning demo (main)..."
make clean
