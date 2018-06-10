#include "bpf_seg6/all.h"

struct bpf_elf_map __section_maps uplink_wrr_sids = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       0,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(struct ip6_addr_t),
   .max_elem       =       3,
   .pinning        =       PIN_GLOBAL_NS,
};

struct bpf_elf_map __section_maps uplink_wrr_weights = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       1,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint32_t),
   .max_elem       =       2,
   .pinning        =       PIN_GLOBAL_NS,
};

struct bpf_elf_map __section_maps uplink_wrr_state = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       1,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint32_t),
   .max_elem       =       3,
   .pinning        =       PIN_GLOBAL_NS,
};

static __attribute__((always_inline))
void build_SRH(char *srh_buf, struct ip6_addr_t *intermediate, struct ip6_addr_t *dst)
{
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->type = 4;
	srh->flags = 0;
	srh->tag = 0;
	srh->hdrlen = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	seg0->hi = dst->hi;
	seg0->lo = dst->lo;

	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(struct ip6_addr_t));
	seg1->hi = intermediate->hi;
	seg1->lo = intermediate->lo;
}

static __attribute__((always_inline))
struct ip6_addr_t *WRR()
{
	struct ip6_addr_t *sid1, *sid2;
	int *w1, *w2;
	int *last_sid, *prev_cw, *gcd;

	int k=0;
	sid1 = map_lookup_elem(&uplink_wrr_sids, &k);
	w1 = map_lookup_elem(&uplink_wrr_weights, &k);
	last_sid = map_lookup_elem(&uplink_wrr_state, &k);

	k++;
	sid2 = map_lookup_elem(&uplink_wrr_sids, &k);
	w2 = map_lookup_elem(&uplink_wrr_weights, &k);
	prev_cw = map_lookup_elem(&uplink_wrr_state, &k);
	
	k++;
	gcd = map_lookup_elem(&uplink_wrr_state, &k);

	if (!w1) return NULL;
	if (!w2) return NULL;
	if (!sid1) return NULL;
	if (!sid2) return NULL;
	if (!last_sid) return NULL;
	if (!prev_cw) return NULL;
	if (!gcd) return NULL;

	struct ip6_addr_t *ret = NULL;
	int i = *last_sid;
	int cw = *prev_cw;

	i = (i+1) % 2;
	if (i == 0) {
		cw = cw - *gcd;
		if (cw <= 0)
		    cw = *w1 >= *w2 ? *w1 : *w2;
	}
	if (i == 0 && *w1 >= cw) {
		ret = sid1;
	} else if (i == 1 && *w2 >= cw) {
		ret = sid2;
	} else {
		i = (i+1) % 2;
		if (i == 0) {
			cw = cw - *gcd;
			if (cw <= 0)
			    cw = *w1 >= *w2 ? *w1 : *w2;
		}
		if (i == 0 && *w1 >= cw)
			ret = sid1;
		else if (i == 1 && *w2 >= cw)
			ret = sid2;
		else
			ret = NULL; // should never happen
	}

	k=0;
	map_update_elem(&uplink_wrr_state, &k, &i ,BPF_ANY);
	k++;
	map_update_elem(&uplink_wrr_state, &k, &cw ,BPF_ANY);

	return ret;
}

__section("main")
int LB(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *cursor   = (void *)(long)skb->data;

	struct ip6_t *ip;
	ip = cursor_advance(cursor, sizeof(struct ip6_t));
	if ((void *)ip + sizeof(*ip) > data_end) 
		return BPF_DROP;

	struct ip6_addr_t *hop = WRR();
	if (hop == NULL)
		return BPF_DROP;

	struct ip6_addr_t *sid_dst;
	int k = 2;
	sid_dst = map_lookup_elem(&uplink_wrr_sids, &k);
	if (sid_dst == NULL)
		return BPF_DROP;

	char srh_buf[40];
	build_SRH(srh_buf, hop, sid_dst);
	lwt_push_encap(skb, BPF_LWT_ENCAP_SEG6, (void *)srh_buf, 40);
	return BPF_OK;	
}

char __license[] __section("license") = "GPL";
