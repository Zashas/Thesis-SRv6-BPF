#include "proto.h"
#include "libseg6.c"

#define SR6_TLV_DM 7

BPF_PERF_OUTPUT(dm_messages);

struct timestamp_ieee1588_v2 {
	uint32_t tv_sec;
	uint32_t tv_nsec;
};

struct sr6_tlv_dm_t {
	unsigned char type; // value TBA by IANA, use NSH+1
	unsigned char len;
	unsigned short reserved;
	unsigned char version:4; // 1
	unsigned char flags:4; // R|T|0|0, R: Query(0),Response(1), T: if tc class, set to 1
	unsigned char cc;
	/* For a Query: 0x0 in-band response, 0x1 out of band, 0x2: no response 
	* For a response: 0x1 success, 0x10-0xFF: errors */
	unsigned short reserved2;
	unsigned char qtf:4; /* timestamp formats */
	unsigned char rtf:4;
	unsigned char rtpf:4;
	unsigned int reserved3:20;
	unsigned int session_id:24; /* set by the querier */
	unsigned char tc;
	struct timestamp_ieee1588_v2 timestamps[4];
	unsigned char sub_tlv[0]; // possible UDP Return Object (URO)
} BPF_PACKET_HEADER;


int DM_recv(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	if (!srh)
		return BPF_DROP;

	struct sr6_tlv_dm_t tlv;
	int cursor = seg6_find_tlv(skb, srh, SR6_TLV_DM, sizeof(tlv));
	if (cursor < 0)
		return BPF_DROP;

	if (bpf_skb_load_bytes(skb, cursor, &tlv, sizeof(tlv)) < 0)
		return BPF_DROP;

	unsigned char query_cc = tlv.cc;

	// only handle version 1, in-band messages, replies and rtf type 3
	if (tlv.version != 1 || tlv.cc != 0x00 || (tlv.flags & 8) == 0 || tlv.rtf != 3)
		return BPF_DROP;

	dm_messages.perf_submit_skb(skb, skb->len, &tlv, sizeof(tlv));
	return BPF_DROP;
}

char __license[] __section("license") = "GPL";
