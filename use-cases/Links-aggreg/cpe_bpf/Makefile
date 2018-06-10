CC = clang
LLC = llc

all: bpf tools

tools:
	clang end_otp_usr.c -o end_otp_usr
	clang uplink_wrr_usr.c -o uplink_wrr_usr


bpf:
	$(CC) -O2 -emit-llvm -g -c end_otp_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o end_otp_bpf.o
	$(CC) -O2 -emit-llvm -g -c uplink_wrr_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o uplink_wrr_bpf.o

