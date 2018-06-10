#include <errno.h>
#include "bpf_seg6/all.h"

struct bpf_elf_map __section_maps powd_inj_sids = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       0,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(struct ip6_addr_t),
   .max_elem       =       2,
   .pinning        =       PIN_GLOBAL_NS,
};

struct bpf_elf_map __section_maps powd_inj_freq_dport = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       1,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint64_t),
   .max_elem       =       2,
   .pinning        =       PIN_GLOBAL_NS,
};

struct bpf_elf_map __section_maps powd_inj_cnt = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       0,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint64_t),
   .max_elem       =       1,
   .pinning        =       PIN_OBJECT_NS,
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

struct uro_v6 {
	unsigned char type; // URO = 131
	unsigned char len; // = 18
	unsigned short dport;
	struct ip6_addr_t daddr;
} BPF_PACKET_HEADER;


static __attribute__((always_inline))
int encap_srh_dm_tlv(struct __sk_buff *skb)
{
	int k = 0;
	struct ip6_addr_t *sid_otp = map_lookup_elem(&powd_inj_sids, &k);
	k++;
	struct ip6_addr_t *sid_uro = map_lookup_elem(&powd_inj_sids, &k);
	uint16_t *uro_dport = (uint16_t *)map_lookup_elem(&powd_inj_freq_dport, &k);
	if (!sid_otp || !sid_uro || !uro_dport)
		return -EFAULT;

	char srh_buf[96];
	memset(srh_buf, 0, sizeof(srh_buf));
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->type = 4;
	srh->hdrlen = 11;
	srh->segments_left = 0;
	srh->first_segment = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	seg0->hi = sid_otp->hi;
	seg0->lo = sid_otp->lo;

	struct sr6_tlv_dm_t *dm = (struct sr6_tlv_dm_t *)((char*) seg0 + sizeof(struct ip6_addr_t));
	dm->type = 7;
	dm->len = sizeof(*dm) - 2;
	dm->version = 1;
	dm->qtf = 3;
	dm->cc = 1;

	uint64_t tx_tstamp = ktime_get_real_ns();
	dm->timestamps[0].tv_sec = htonl((uint32_t) (tx_tstamp / 1000000000));
	dm->timestamps[0].tv_nsec = htonl((uint32_t) (tx_tstamp % 1000000000));

	struct uro_v6 *uro = (struct uro_v6 *) ((char *)dm + sizeof(*dm));
	uro->type = 131;
	uro->dport = *uro_dport;
	uro->len = sizeof(*uro) - 2;
	uro->daddr.hi = sid_uro->hi;
	uro->daddr.lo = sid_uro->lo;

	struct sr6_tlv *tlv_pad = (struct sr6_tlv *) ((char *)uro + sizeof(*uro));
	tlv_pad->type = 4;
	tlv_pad->len = 2;

	return lwt_push_encap(skb, BPF_LWT_ENCAP_SEG6, (void *)srh_buf, sizeof(srh_buf));
}

__section("main")
int injector(struct __sk_buff *skb)
{
	int k = 0;
	uint64_t *counter = map_lookup_elem(&powd_inj_cnt, &k);
	uint64_t *freq = map_lookup_elem(&powd_inj_freq_dport, &k);

	if (!counter || !freq)
		return BPF_OK;

	__sync_fetch_and_add(counter, 1); // atomic increment
	if (*counter >= *freq) {
		uint64_t zero = 0;
		map_update_elem(&powd_inj_cnt, &k, &zero, BPF_ANY);
		if (encap_srh_dm_tlv(skb)) {
			printt("drop\n");
			return BPF_DROP;
		}

		return BPF_OK;
	}

	return BPF_OK;	
}

char __license[] __section("license") = "GPL";
