#include "bpf_seg6/all.h"
#include "libseg6.c"

#define SR6_TLV_DM 7
#define SR6_TLV_URO 131

struct bpf_elf_map __section_maps end_otp_delta = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       43,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint32_t),
   .max_elem       =       4,
   .pinning        =       PIN_GLOBAL_NS,
};


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

__section("end_otp")
int End_OTP(struct __sk_buff *skb) {
	// first thing, fetch the monotonic timestamp, since we do not want the
	// following operations to be included in the delay measurement
	uint64_t timestamp = ktime_get_ns();

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
	} else if (tlv.cc != 0x00) { // we are only capable of handling in-band replies
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

	int id = 0;
	uint32_t *clk_diff_sec = map_lookup_elem(&end_otp_delta, &id);
	id++;
	uint32_t *clk_diff_ns = map_lookup_elem(&end_otp_delta, &id);
	if (!clk_diff_sec || !clk_diff_ns) {
		tlv.cc = 0x1C;
		goto send;
	}

	uint32_t ts_sec = (uint32_t) (timestamp / 1000000000);
	uint32_t ts_ns = (uint32_t) (timestamp % 1000000000);
	ts_ns += *clk_diff_ns;
	if (ts_ns > 1000000000) {
		ts_sec += 1;
		ts_ns = ts_ns - 1000000000;
	}
	ts_sec += *clk_diff_sec;
	tlv.timestamps[1].tv_sec = htonl(ts_sec);
	tlv.timestamps[1].tv_nsec = htonl(ts_ns);

	// this is a BPF limitation, we can not obtain two different HW timestamps
	tlv.timestamps[2].tv_sec = tlv.timestamps[1].tv_sec;
	tlv.timestamps[2].tv_nsec = tlv.timestamps[1].tv_nsec;

send:
	if (query_cc == 0x00) { // in-band
		if (bpf_lwt_seg6_store_bytes(skb, cursor, &tlv, sizeof(tlv)) < 0)
			return BPF_DROP;

		return BPF_OK;
	} else {
		return BPF_DROP;
	}
}

char __license[] __section("license") = "GPL";
