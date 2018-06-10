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

int main(int argc, char *argv[])
{
	struct in6_addr sid_otp, sid_uro;
	uint64_t frequency, dport;

	if (argc != 5) {
		printf("Expected: %s SID-OTP FREQUENCY CONTROLLER-IP6 CONTROLLER-DPORT\n", argv[0]);
		return -1;
	}

	if (!inet_pton(AF_INET6, argv[1], &sid_otp) || !inet_pton(AF_INET6, argv[3], &sid_uro)) {
		printf("Error: SIDs and CONTROLLER-IP6 must be valid IPv6 addresses.\n");
		printf("Expected: %s SID-OTP FREQUENCY CONTROLLER-IP6 CONTROLLER-DPORT\n", argv[0]);
		return -1;
	}

	frequency = strtoll(argv[2], NULL, 10);
	dport = strtoll(argv[4], NULL, 10);
	dport = htons((uint16_t) dport & 65535);
	if (frequency <= 0) {
		printf("Error: frequency must be a strictly positive number.\n");
		printf("Expected: %s SID-OTP FREQUENCY CONTROLLER-IP6 CONTROLLER-DPORT\n", argv[0]);
		return -1;
	}

	if (dport <= 0 || dport >= 65536) {
		printf("Error: CONTROLLER-DPORT must be a number between 1 and 65535.\n");
		printf("Expected: %s SID-OTP FREQUENCY CONTROLLER-IP6 CONTROLLER-DPORT\n", argv[0]);
		return -1;
	}

	union bpf_attr attr_obj = {};
	int map_fd[2];

	char *map_paths[] = {
		"/sys/fs/bpf/ip/globals/powd_inj_freq_dport",
		"/sys/fs/bpf/ip/globals/powd_inj_sids"
	};

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
	bpf_update_elem(map_fd[0], &key, &frequency, BPF_ANY);
	bpf_update_elem(map_fd[1], &key, &sid_otp, BPF_ANY);
	key++;
	bpf_update_elem(map_fd[0], &key, &dport, BPF_ANY);
	bpf_update_elem(map_fd[1], &key, &sid_uro, BPF_ANY);

	return 0;
}
