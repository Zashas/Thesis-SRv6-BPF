CC = clang
LLC = llc

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

.PHONY: bpf

all: $(OBJS)

clean:
	rm $(OBJS)

%.o: %.c
	$(CC) -Wall -O2 -emit-llvm -g -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@
