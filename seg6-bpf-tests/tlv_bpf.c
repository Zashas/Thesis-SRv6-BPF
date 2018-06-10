#include <errno.h>
#include "bpf_seg6/all.h"
#include "libseg6.c"

struct sr6_tlv_nsh {
    unsigned char type;
    unsigned char len;
    unsigned char flags;
    unsigned char value[5];
} BPF_PACKET_HEADER;

__section("add_8")
int do_add_8(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_nsh tlv;
    tlv.type = 6; // NSH
    tlv.len = 6;
    tlv.flags = 0;
    tlv.value[0] = 1;
    tlv.value[1] = 2;
    tlv.value[2] = 3;
    tlv.value[3] = 4;
    tlv.value[4] = 5;
    int err = seg6_add_tlv(skb,srh, (srh->hdrlen+1) << 3, (struct sr6_tlv_t *)&tlv, 8);

    return (err) ? BPF_DROP : BPF_OK;
}

__section("add_6")
int do_add_6(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_nsh tlv;
    tlv.type = 6; // NSH
    tlv.len = 4;
    tlv.flags = 0;
    tlv.value[0] = 1;
    tlv.value[1] = 2;
    tlv.value[2] = 3;
    int err = seg6_add_tlv(skb,srh, (srh->hdrlen+1) << 3, (struct sr6_tlv_t *)&tlv, 6);

    return (err) ? BPF_DROP : BPF_OK;
}


__section("add_ingr")
int do_add_ingr(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.value, 0, 16);
    tlv.value[15] = 1;
    tlv.value[0] = 0xfc;
    int err = seg6_add_tlv(skb,srh, (srh->hdrlen+1) << 3, (struct sr6_tlv_t *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
}

__section("add_ingr_no_offset")
int do_add_ingr_no_offset(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.value, 0, 16);
    tlv.value[15] = 1;
    tlv.value[0] = 0xfc;
    int err = seg6_add_tlv(skb,srh, -1, (struct sr6_tlv_t *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
}

__section("add_ingr_mid")
int do_add_ingr_mid(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.value, 0, 16);
    tlv.value[15] = 0xef;
    tlv.value[14] = 0xbe;
    tlv.value[0] = 0xfc;
    int err = seg6_add_tlv(skb,srh, 8 + (srh->first_segment+1)*16 + 20, (struct sr6_tlv_t *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
}



__section("add_wrong_offset")
int do_add_ingr_wrong_offset(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.value, 0, 16);
    tlv.value[15] = 1;
    tlv.value[0] = 0xfc;
    int err = seg6_add_tlv(skb,srh, 11, (struct sr6_tlv_t *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
}

__section("add_opaq_begin")
int do_add_opaq_begin(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 3;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.value, 0, 16);
    tlv.value[15] = 0x42;
    int err = seg6_add_tlv(skb,srh, 8+(srh->first_segment+1)*16, (struct sr6_tlv_t *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_first")
int do_del_first(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    /*
    struct sr6_tlv_t *tlv = (struct sr6_tlv_t *)((char *)srh+8+(srh->first_segment+1)*16);
    if ((void *)tlv > data_end) // Check needed otherwise filter not accepted by the kernel
        return BPF_OK;*/

    int err = seg6_delete_tlv(skb, srh, 8+(srh->first_segment+1)*16);
    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_20")
int do_del_20(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    int err = seg6_delete_tlv(skb, srh, 8+(srh->first_segment+1)*16+20);
    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_24")
 int do_del_24(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = seg6_get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    int err = seg6_delete_tlv(skb, srh, 8+(srh->first_segment+1)*16+24);
    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_24_hmac")
 int do_del_24_hmac(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	int offset = (char *)srh - (char *)(long)skb->data;
	if (srh == NULL)
		return BPF_DROP;

	uint8_t flags = srh->flags & (~SR6_FLAG_HMAC);

	int err = seg6_delete_tlv(skb, srh, 8+(srh->first_segment+1)*16+24);
	if (err)
		return BPF_DROP;

	lwt_seg6_store_bytes(skb, offset + offsetof(struct ip6_srh_t, flags), (void *) &flags, sizeof(flags));
	return BPF_OK;
}


char __license[] __section("license") = "GPL";
