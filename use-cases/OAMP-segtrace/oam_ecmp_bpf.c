#include "proto.h"
#include "libseg6.c"

#define SR6_TLV_OAM_NH_REQ 100
#define SR6_TLV_OAM_NH_REPLY 101
#define MAX_NH 16

BPF_HASH(link_local_table, struct ip6_addr_t, struct ip6_addr_t);

struct oam_nh_request_t {
	uint8_t tlv_type;
	uint8_t len;
	uint16_t session_id;
	struct ip6_addr_t dst;
} BPF_PACKET_HEADER;

struct oam_nh_reply_t {
	uint8_t tlv_type;
	uint8_t len;
	uint8_t nb_nh;
	uint8_t reserved;
	struct ip6_addr_t nexthops[MAX_NH];
} BPF_PACKET_HEADER;

int SEG6_OAM(struct __sk_buff *skb) {
	struct oam_nh_request_t tlv_req;
	struct oam_nh_reply_t tlv_reply;
	int ret;

	struct ip6_srh_t *srh = seg6_get_srh(skb);
	if (!srh)
		return BPF_DROP;

	struct ip6_t *ip = (void *)(long)skb->data;
	if ((void *)ip + sizeof(*ip) > (void *)(long)skb->data_end)
		return BPF_DROP;

	int cursor = seg6_find_tlv(skb, srh, SR6_TLV_OAM_NH_REQ, sizeof(tlv_req));
	if (cursor < 0) // no OAM TLV found, nevermind
		return BPF_OK;
	if (bpf_skb_load_bytes(skb, cursor, &tlv_req, sizeof(tlv_req)) < 0)
		return BPF_DROP; // error

	memset(&tlv_reply.nexthops, 0, MAX_NH << 4);
	ret = bpf_ipv6_fib_multipath_nh(skb, &tlv_req.dst, 16, &tlv_reply.nexthops, MAX_NH << 4);
	if (ret < 0)
		return BPF_DROP;

	tlv_reply.nb_nh = ret;
	tlv_reply.reserved = 0;
	tlv_reply.tlv_type = SR6_TLV_OAM_NH_REPLY;
	tlv_reply.len = (tlv_reply.nb_nh << 4) + 2 * sizeof(uint8_t);

	// Convert potential link local addresses to global ones
	#pragma clang loop unroll(full)
	for (int i=0; i < MAX_NH; i++) {
		if (i >= tlv_reply.nb_nh)
			break;

		struct ip6_addr_t *addr = &tlv_reply.nexthops[i];
		// check if addr is in fe80::/10
		/*if ((bpf_htonll(addr->hi) >> 56) == 0xfe &&
		    !((((bpf_htonll(addr->hi) >> 54) & 3) ^ 2))) {*/
			struct ip6_addr_t *gaddr = link_local_table.lookup(addr);
			if (gaddr != NULL)
				*addr = *gaddr;
		//}
	}

	ret = seg6_add_tlv(skb, srh, -1, (struct sr6_tlv_t *)&tlv_reply, tlv_reply.len + 2);
	if (ret)
		return BPF_DROP;
	return BPF_OK;
}

char __license[] __section("license") = "GPL";
