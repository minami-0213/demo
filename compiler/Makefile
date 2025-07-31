CC=clang

all: my-clang my-clang++

my-clang: test-clang.c
	$(CC) $^ -o $@

my-clang++: test-clang.c
	$(CC) $^ -o $@

debug: test-clang.c
	$(CC) $^ -DDEBUG_CLANG -o my-clang
	$(CC) $^ -DDEBUG_CLANG -o my-clang++

clean:
	rm my-clang my-clang++

.PHONY: clean