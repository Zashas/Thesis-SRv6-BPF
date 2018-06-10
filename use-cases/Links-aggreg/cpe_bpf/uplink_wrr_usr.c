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

int get_gcd(int a, int b)
{
	int c;
	while (a != 0) {
		c = a;
		a = b%a;
		b = c;
	}
	return b;
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
	struct in6_addr sid1, sid2, sid_agg;
	int w1, w2, gcd;
	int cw = 0;
	int last_sid = -1;

	if (argc != 6) {
		printf("Error, needed parameters: ./uplink_wrr_usr SID-AGG SID1 W1 SID2 W2");
		return -1;
	}

	if (!inet_pton(AF_INET6, argv[2], &sid1) || !inet_pton(AF_INET6, argv[4], &sid2) || !inet_pton(AF_INET6, argv[1], &sid_agg)) {
		printf("Error: SIDs must be valid IPv6 addresses.");
		printf("./uplink_wrr_usr SID1 W1 SID2 W2");
		return -1;
	}

	w1 = atoi(argv[3]);
	w2 = atoi(argv[5]);
	if (w1 <= 0 || w2 <= 0) {
		printf("Error: weights must be positive numbers.");
		printf("./uplink_wrr_usr SID1 W1 SID2 W2");
		return -1;
	}
	gcd = get_gcd(w1, w2);

	union bpf_attr attr_obj = {};
	int map_fd[3];

	char *map_paths[] = {
		"/sys/fs/bpf/ip/globals/uplink_wrr_sids",
		"/sys/fs/bpf/ip/globals/uplink_wrr_weights",
		"/sys/fs/bpf/ip/globals/uplink_wrr_state"
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
	bpf_update_elem(map_fd[0], &key, &sid1, BPF_ANY);
	bpf_update_elem(map_fd[1], &key, &w1, BPF_ANY);
	bpf_update_elem(map_fd[2], &key, &last_sid, BPF_ANY);

	key++;
	bpf_update_elem(map_fd[0], &key, &sid2, BPF_ANY);
	bpf_update_elem(map_fd[1], &key, &w2, BPF_ANY);
	bpf_update_elem(map_fd[2], &key, &cw, BPF_ANY);

	key++;
	bpf_update_elem(map_fd[0], &key, &sid_agg, BPF_ANY);
	bpf_update_elem(map_fd[2], &key, &gcd, BPF_ANY);

	return 0;
}
