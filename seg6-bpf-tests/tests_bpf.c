#include "bpf_seg6/all.h"
#include "libseg6.c"

#define EFAULT 14

__section("pass")
int do_pass(struct __sk_buff *skb) {
	return BPF_OK; // packet continues
}

__section("drop")
int do_drop(struct __sk_buff *skb) {
	return BPF_DROP; // packet dropped
}

__section("inc_tag")
int do_inc_tag(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	int offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, tag);
	if (srh == NULL)
		return BPF_DROP;

	uint16_t tag = ntohs(srh->tag);
	tag = htons(tag+1);
	lwt_seg6_store_bytes(skb, offset, (void *) &tag, sizeof(srh->tag));
	return BPF_OK;
}

__section("alert")
int do_alert(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	int offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, flags);
	if (srh == NULL)
		return BPF_DROP;

	uint8_t flags = srh->flags | SR6_FLAG_ALERT;
	lwt_seg6_store_bytes(skb, offset, (void *) &flags, sizeof(flags));
	return BPF_OK;
}

__section("end_x")
int do_end_x(struct __sk_buff *skb) {
	struct ip6_addr_t addr;
	unsigned long long hi = 0xfc42000000000000;
	unsigned long long lo = 0x1;
	addr.lo = htonll(lo);
	addr.hi = htonll(hi);
	int err = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_X, (void *)&addr,sizeof(addr)); // End.X to fc00::14
	if (err)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("end_t")
int do_end_t(struct __sk_buff *skb)
{
	int table = 42;
	int err = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_T, (void *)&table, sizeof(table));
	if (err)
		return BPF_DROP;

	return BPF_REDIRECT;
}

__section("end_b6")
int do_end_b6(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_B6, (void *)srh, sizeof(srh_buf));
	if (ret != 0) {
		return BPF_DROP;
	}
	return BPF_REDIRECT;
}

__section("b6_encap")
int do_b6_encap(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_B6_ENCAP, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("b6_encap_wrong")
int do_b6_encap_wrong(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 2;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_B6_ENCAP, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;

	return BPF_REDIRECT;
}

__section("long_b6_encap")
int do_long_b6_encap(struct __sk_buff *skb) {
	char srh_buf[88]; // room for 5 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 10;
	srh->type = 4;
	srh->segments_left = 4;
	srh->first_segment = 4;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr_t *seg2 = (struct ip6_addr_t *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr_t *seg3 = (struct ip6_addr_t *)((char*) seg2 + sizeof(*seg2));
	struct ip6_addr_t *seg4 = (struct ip6_addr_t *)((char*) seg3 + sizeof(*seg3));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	seg2->hi = seg0->hi;
	lo = 0x3;
	seg2->lo = htonll(lo);

	seg3->hi = seg0->hi;
	lo = 0x4;
	seg3->lo = htonll(lo);

	seg4->hi = seg0->hi;
	lo = 0x5;
	seg4->lo = htonll(lo);

	int ret = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_B6_ENCAP, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("long_b6")
int do_long_b6(struct __sk_buff *skb) {
	char srh_buf[88]; // room for 5 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 10;
	srh->type = 4;
	srh->segments_left = 4;
	srh->first_segment = 4;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr_t *seg2 = (struct ip6_addr_t *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr_t *seg3 = (struct ip6_addr_t *)((char*) seg2 + sizeof(*seg2));
	struct ip6_addr_t *seg4 = (struct ip6_addr_t *)((char*) seg3 + sizeof(*seg3));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	seg2->hi = seg0->hi;
	lo = 0x3;
	seg2->lo = htonll(lo);

	seg3->hi = seg0->hi;
	lo = 0x4;
	seg3->lo = htonll(lo);

	seg4->hi = seg0->hi;
	lo = 0x5;
	seg4->lo = htonll(lo);

	int ret = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_B6, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("push_encap")
int do_push_encap(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = lwt_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_OK;
}

__section("push_encap_wrong")
int do_push_encap_wrong(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 2;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = lwt_push_encap(skb, 1, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;

	return BPF_REDIRECT;
}

__section("long_encap_push")
int do_long_encap_push(struct __sk_buff *skb) {
	char srh_buf[88]; // room for 5 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 10;
	srh->type = 4;
	srh->segments_left = 4;
	srh->first_segment = 4;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr_t *seg2 = (struct ip6_addr_t *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr_t *seg3 = (struct ip6_addr_t *)((char*) seg2 + sizeof(*seg2));
	struct ip6_addr_t *seg4 = (struct ip6_addr_t *)((char*) seg3 + sizeof(*seg3));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	seg2->hi = seg0->hi;
	lo = 0x3;
	seg2->lo = htonll(lo);

	seg3->hi = seg0->hi;
	lo = 0x4;
	seg3->lo = htonll(lo);

	seg4->hi = seg0->hi;
	lo = 0x5;
	seg4->lo = htonll(lo);

	int ret = lwt_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("long_encap_inline")
int do_long_encap_inline(struct __sk_buff *skb) {
	char srh_buf[88]; // room for 5 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 10;
	srh->type = 4;
	srh->segments_left = 4;
	srh->first_segment = 4;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr_t *seg2 = (struct ip6_addr_t *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr_t *seg3 = (struct ip6_addr_t *)((char*) seg2 + sizeof(*seg2));
	struct ip6_addr_t *seg4 = (struct ip6_addr_t *)((char*) seg3 + sizeof(*seg3));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	seg2->hi = seg0->hi;
	lo = 0x3;
	seg2->lo = htonll(lo);

	seg3->hi = seg0->hi;
	lo = 0x4;
	seg3->lo = htonll(lo);

	seg4->hi = seg0->hi;
	lo = 0x5;
	seg4->lo = htonll(lo);

	int ret = lwt_push_encap(skb, 1, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_OK;
}

__section("encap_inline_3seg")
int do_encap_inline_3seg(struct __sk_buff *skb) {
	char srh_buf[56]; // room for 3 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 6;
	srh->type = 4;
	srh->segments_left = 2;
	srh->first_segment = 2;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr_t *seg2 = (struct ip6_addr_t *)((char*) seg1 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	seg2->hi = seg0->hi;
	lo = 0x3;
	seg2->lo = htonll(lo);

	int ret = lwt_push_encap(skb, 1, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("wrong_stores")
int do_wrong_stores(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	if (srh == NULL)
		return BPF_DROP;

	char value = 42;
	int offset, err;
	offset = sizeof(struct ip6_t) - 4;
	err = lwt_seg6_store_bytes(skb, offset, (void *) &value, sizeof(char));
	if (err != -EFAULT)
		return BPF_DROP;

	offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, nexthdr);
	for(int i=0; i < 5; i++) { // nexthdr to first_segment included
		err = lwt_seg6_store_bytes(skb, offset, (void *) &value, sizeof(char));
		if (err != -EFAULT)
			return BPF_DROP;
		offset++;
	}

	offset = sizeof(struct ip6_t) + sizeof(struct ip6_srh_t) + 10;
	err = lwt_seg6_store_bytes(skb, offset, (void *) &value, sizeof(char));
	if (err != -EFAULT)
		return BPF_DROP;

	offset = sizeof(struct ip6_t) + sizeof(struct ip6_srh_t) + 1000;
	err = lwt_seg6_store_bytes(skb, offset, (void *) &value, sizeof(char));
	if (err != -EFAULT)
		return BPF_DROP;

	return BPF_OK;
}

__section("wrong_adjusts")
int do_wrong_adjusts(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	if (srh == NULL)
		return BPF_DROP;

	int offset, err;
	offset = sizeof(struct ip6_t) - 4;
	err = lwt_seg6_adjust_srh(skb, offset, 4);
	if (err != -EFAULT)
		return BPF_DROP;

	offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, nexthdr);
	#pragma clang loop unroll(full)
	for(int i=0; i < 40; i++) { // nexthdr to 2 segments included
		err = lwt_seg6_adjust_srh(skb, offset, 4);
		if (err != -EFAULT)
			return BPF_DROP; 

		offset++;
	}
	offset = sizeof(struct ip6_t) + sizeof(struct ip6_srh_t) + 32 + 30;
	err = lwt_seg6_adjust_srh(skb, offset, -20);
	if (err != -EFAULT)
		return BPF_DROP;

	offset = sizeof(struct ip6_t) + sizeof(struct ip6_srh_t) + 32 + 48;
	err = lwt_seg6_adjust_srh(skb, offset, 4);
	if (err != -EFAULT)
		return BPF_DROP;

	return BPF_OK;
}

__section("invalid_hdrlen")
int do_invalid_hdrlen(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	if (srh == NULL)
		return BPF_DROP;

	// Add a 4 bytes TLV to the end of the SRH, this will make the SRH
	// invalid
	int err = lwt_seg6_adjust_srh(skb, 40 + ((srh->hdrlen + 1) << 3), 4);
	if (err)
		printt("seg6bpf_tests/just_adjust: adjust_srh failed - error %d !\n", err);

	return BPF_OK;
}

__section("push_encap_udp")
int do_push_encap_udp(struct __sk_buff *skb) {
	uint8_t *ipver;
	void *data_end = (void *)(long)skb->data_end;
	void *cursor   = (void *)(long)skb->data;
	ipver = (uint8_t*) cursor;

	if ((void *)ipver + sizeof(*ipver) > data_end) 
		return BPF_OK;

	if ((*ipver >> 4) != 6) 
		return BPF_OK;

	struct ip6_t *ip;
	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end) 
		return BPF_OK;

	if (ip->next_header != 17) 
		return BPF_OK;

	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr_t *seg0 = (struct ip6_addr_t *)((char*) srh + sizeof(*srh));
	struct ip6_addr_t *seg1 = (struct ip6_addr_t *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = lwt_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_OK;
}

__section("end_dt6")
int do_end_dt6(struct __sk_buff *skb)
{
	int table = 254;
	int err = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_DT6, (void *)&table, sizeof(table));
	if (err)
		return BPF_DROP;

	return BPF_REDIRECT;
}

char __license[] __section("license") = "GPL";
