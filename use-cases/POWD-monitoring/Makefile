CC = clang
LLC = llc

all: bpf tools

tools:
	clang dm_injector_usr.c -o dm_injector_usr

bpf:
	$(CC) -O2 -emit-llvm -c dm_injector_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o dm_injector_bpf.o

.PHONY: tools
