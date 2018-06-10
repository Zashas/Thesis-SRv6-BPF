#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <time.h>

uint32_t mono_real_diff_ns()
{
	struct timespec mono, real;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	if (mono.tv_nsec > real.tv_nsec)
		return (uint32_t) (1000000000 - mono.tv_nsec + real.tv_nsec);
	
	return (uint32_t) (real.tv_nsec - mono.tv_nsec);
}

uint32_t mono_real_diff_sec()
{
	struct timespec mono, real;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);

	if (mono.tv_nsec > real.tv_nsec)
		return (uint32_t) (real.tv_sec - mono.tv_sec - 1);

	return (uint32_t) (real.tv_sec - mono.tv_sec);
}

int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, size);
#else
	fprintf(stderr, "No bpf syscall, kernel headers too old?\n");
	errno = ENOSYS;
	return -1;
#endif
}

__u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int bpf_update_elem(int fd, void *key, void *value, uint64_t flags)
{
	union bpf_attr attr = {};
	attr.map_fd = fd;
	attr.key    = bpf_ptr_to_u64(key);
	attr.value  = bpf_ptr_to_u64(value);;
	attr.flags  = flags;

	static int nb = 0;
	nb++;
	int ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if (ret < 0) {
		fprintf(stderr, "Map update #%d failed: %s\n", nb, strerror(errno));
	}

	return ret;
}

/* Main function */

int main (int argc, char *argv[])
{
	union bpf_attr attr_obj = {};
	int map_fd[1];

	char *map_paths[] = {"/sys/fs/bpf/ip/globals/end_otp_delta"};

	for(int i=0; i < sizeof(map_fd)/sizeof(int); i++) {
		attr_obj.map_fd = 0;
		attr_obj.pathname = bpf_ptr_to_u64(map_paths[i]);
		map_fd[i] = bpf(BPF_OBJ_GET, &attr_obj, sizeof(attr_obj));
		if (map_fd[i] <= 0) {
			fprintf(stderr, "Fetching map failed: %s\n", strerror(errno));
			return -1;
		}
	}

	uint32_t key = 0;
	uint32_t delta_s = mono_real_diff_sec();
	bpf_update_elem(map_fd[0], &key, &delta_s, BPF_ANY);

	uint32_t delta_ns = mono_real_diff_ns();
	key++;
	bpf_update_elem(map_fd[0], &key, &delta_ns, BPF_ANY);

	return 0;
}
