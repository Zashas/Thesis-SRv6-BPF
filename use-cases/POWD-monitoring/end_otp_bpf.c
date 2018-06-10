#include <linux/seg6_local.h>
#include "libseg6.c"

#define SR6_TLV_DM 7
#define SR6_TLV_URO 131

BPF_PERF_OUTPUT(oob_dm_requests);

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

struct uro_v6 {
	unsigned char type; // URO = 131
	unsigned char len; // = 18
	unsigned short dport;
	struct ip6_addr_t daddr;
} BPF_PACKET_HEADER;

struct oob_request {
	struct sr6_tlv_dm_t response;
	struct uro_v6 uro;
};

int End_OTP(struct __sk_buff *skb) {
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
	if (tlv.version != 1) {
		tlv.cc = 0x11;
		goto send;
	} else if (tlv.cc > 0x02) {
		tlv.cc = 0x12;
		goto send;
	} else if (tlv.flags & 8) {
		tlv.cc = 0x11;
		goto send;
	} else if (tlv.rtf != 0 && tlv.rtf != 3) { // Unsupported already set RTF type
		tlv.cc = 0x10; // Generic error
		goto send;
	}

	tlv.flags |= 8; // DM TLV becomes a response
	tlv.rtf = 3;

	uint64_t rx_tstamp = bpf_skb_get_tstamp(skb);
	tlv.timestamps[1].tv_sec = bpf_htonl((uint32_t) (rx_tstamp / 1000000000));
	tlv.timestamps[1].tv_nsec = bpf_htonl((uint32_t) (rx_tstamp % 1000000000));

	if (query_cc == 0x00) { // in case of a two-way delay measurement
		uint64_t tx_tstamp = bpf_ktime_get_real_ns();
		tlv.timestamps[2].tv_sec = bpf_htonl((uint32_t) (tx_tstamp / 1000000000));
		tlv.timestamps[2].tv_nsec = bpf_htonl((uint32_t) (tx_tstamp % 1000000000));
	}

send:
	if (query_cc == 0x00) { // in-band
		if (bpf_lwt_seg6_store_bytes(skb, cursor, &tlv, sizeof(tlv)) < 0)
			return BPF_DROP;

		return BPF_OK;
	} else if (query_cc == 0x01) { // out-of-band, sending to userspace daemon
		struct oob_request req;
		memcpy(&req.response, &tlv, sizeof(tlv));

		cursor = seg6_find_tlv(skb, srh, SR6_TLV_URO, sizeof(req.uro));
		if (cursor < 0)
			return BPF_DROP;

		if (bpf_skb_load_bytes(skb, cursor, &req.uro, sizeof(req.uro)) < 0)
			return BPF_DROP;

		oob_dm_requests.perf_submit_skb(skb, skb->len, &req, sizeof(req));

		int table = 254;
		int err = bpf_lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_DT6, (void *)&table, sizeof(table));
		if (err)
			return BPF_DROP;

		return BPF_REDIRECT;
	} else {
		return BPF_DROP;
	}
}

char __license[] __section("license") = "GPL";
