CC=./compiler/my-clang 

all: main test

main: main.c 
	$(CC) $^ -g -O0 -o $@

test: main.c
	$(CC) $^ -O0 -emit-llvm -S -o main.ll

clean:
	rm main *.ll

.PHONY: clean test all