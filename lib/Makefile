# Makefile for taint analysis project

# 编译为 IR
IRFLAGS = -emit-llvm -S

# 工具定义
LLVM_CONFIG := llvm-config-10
CLANGXX := clang++-10
CLANG := clang-10
OPT := opt-10
CFLAGS1 := -fsanitize=dataflow -mllvm -dfsan-abilist=../rule/libabi.txt
CFLAGS2 := -fsanitize=dataflow -mllvm -dfsan-abilist=../rule/testabi.txt

# 获取 LLVM 编译标志
LLVM_CXXFLAGS := $(shell $(LLVM_CONFIG) --cxxflags)
LLVM_LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags)
LLVM_LIBS := $(shell $(LLVM_CONFIG) --libs core)
LLVM_SYSLIBS := $(shell $(LLVM_CONFIG) --system-libs)

all: libio.so liblog.so MyPass.so
# 编译运行时库
libio.so: io_wrapper.c
	$(CLANG) -fPIC -shared $< -o $@

liblog.so: log.c
	$(CLANG) $(CFLAGS1) -fPIC -shared $< -o $@

# 编译 LLVM Pass
MyPass.so: MyPass.cpp
	$(CLANGXX) -fno-rtti -fPIC -shared $< -o $@ \
		$(LLVM_CXXFLAGS) $(LLVM_LDFLAGS) $(LLVM_LIBS) $(LLVM_SYSLIBS)

# 清理
clean:
	rm -f *.a *.so *.o main .*.o .*.bc *.ll

# 伪目标声明
.PHONY: all clean