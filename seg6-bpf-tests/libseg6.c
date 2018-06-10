#include <errno.h>
#define bpf_skb_load_bytes skb_load_bytes
#define bpf_lwt_seg6_adjust_srh lwt_seg6_adjust_srh
#define bpf_lwt_seg6_store_bytes lwt_seg6_store_bytes

#include "bpf_seg6/all.h"
#define TLV_ITERATIONS 16

__attribute__((always_inline))
struct ip6_srh_t *seg6_get_srh(struct __sk_buff *skb)
{
	void *cursor, *data_end;
	struct ip6_srh_t *srh;
	struct ip6_t *ip;
	uint16_t opt_len;
	uint8_t *ipver;

	data_end = (void *)(long)skb->data_end;
	cursor = (void *)(long)skb->data;
	ipver = (uint8_t *)cursor;

	if ((void *)ipver + sizeof(*ipver) > data_end)
		return NULL;

	if ((*ipver >> 4) != 6)
		return NULL;

	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end)
		return NULL;

	if (ip->next_header != 43)
		return NULL;
	
	// skipping possible destination or hop-by-hop header
	if (ip->next_header == 0 || ip->next_header == 60) {
		if ((void *)cursor + 2 > data_end)
			return NULL;
		opt_len = (1 + (uint16_t) *((uint8_t *) cursor + 1)) << 3;
		if ((void *)cursor + opt_len > data_end)
			return NULL;
		cursor_advance(cursor, opt_len);
	}

	// possible destination header
	if (ip->next_header == 60) { 
		if ((void *)cursor + 2 > data_end)
			return NULL;
		opt_len = (1 + (uint16_t) *((uint8_t *) cursor + 1)) << 3;
		if ((void *)cursor + opt_len > data_end)
			return NULL;
		cursor_advance(cursor, opt_len);
	}

	srh = cursor_advance(cursor, sizeof(*srh));
	if ((void *)srh + sizeof(*srh) > data_end)
		return NULL;

	if (srh->type != 4)
		return NULL;

	return srh;
}

__attribute__((always_inline))
int __update_tlv_pad(struct __sk_buff *skb, uint32_t new_pad,
		     uint32_t old_pad, uint32_t pad_off)
{
	int err;

	if (new_pad != old_pad) {
		err = bpf_lwt_seg6_adjust_srh(skb, pad_off,
					  (int) new_pad - (int) old_pad);
		if (err)
			return err;
	}

	if (new_pad > 0) {
		char pad_tlv_buf[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0};
		struct sr6_tlv_t *pad_tlv = (struct sr6_tlv_t *) pad_tlv_buf;

		pad_tlv->type = SR6_TLV_PADDING;
		pad_tlv->len = new_pad - 2;

		err = bpf_lwt_seg6_store_bytes(skb, pad_off,
					       (void *)pad_tlv_buf, new_pad);
		if (err)
			return err;
	}

	return 0;
}

__attribute__((always_inline))
int __is_valid_tlv_boundary(struct __sk_buff *skb, struct ip6_srh_t *srh,
			    uint32_t *tlv_off, uint32_t *pad_size,
			    uint32_t *pad_off)
{
	uint32_t srh_off, cur_off;
	int offset_valid = 0;
	int err;

	srh_off = (char *)srh - (char *)(long)skb->data;
	// cur_off = end of segments, start of possible TLVs
	cur_off = srh_off + sizeof(*srh) +
		sizeof(struct ip6_addr_t) * (srh->first_segment + 1);

	*pad_off = 0;

	// we can only go as far as ~10 TLVs due to the BPF max stack size
	#pragma clang loop unroll(full)
	for (int i = 0; i < TLV_ITERATIONS; i++) {
		struct sr6_tlv_t tlv;

		if (cur_off == *tlv_off)
			offset_valid = 1;

		if (cur_off >= srh_off + ((srh->hdrlen + 1) << 3))
			break;

		err = bpf_skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv));
		if (err)
			return err;

		if (tlv.type == SR6_TLV_PADDING) {
			*pad_size = tlv.len + sizeof(tlv);
			*pad_off = cur_off;

			if (*tlv_off == srh_off) {
				*tlv_off = cur_off;
				offset_valid = 1;
			}
			break;

		} else if (tlv.type == SR6_TLV_HMAC) {
			break;
		}

		cur_off += sizeof(tlv) + tlv.len;
	} // we reached the padding or HMAC TLVs, or the end of the SRH

	if (*pad_off == 0)
		*pad_off = cur_off;

	if (*tlv_off == -1)
		*tlv_off = cur_off;
	else if (!offset_valid)
		return -EINVAL;

	return 0;
}

__attribute__((always_inline))
int seg6_add_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, uint32_t tlv_off,
		 struct sr6_tlv_t *itlv, uint8_t tlv_size)
{
	uint32_t srh_off = (char *)srh - (char *)(long)skb->data;
	uint8_t len_remaining, new_pad;
	uint32_t pad_off = 0;
	uint32_t pad_size = 0;
	uint32_t partial_srh_len;
	int err;

	if (tlv_off != -1)
		tlv_off += srh_off;

	if (itlv->type == SR6_TLV_PADDING || itlv->type == SR6_TLV_HMAC)
		return -EINVAL;

	err = __is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err)
		return err;

	err = bpf_lwt_seg6_adjust_srh(skb, tlv_off, sizeof(*itlv) + itlv->len);
	if (err)
		return err;

	err = bpf_lwt_seg6_store_bytes(skb, tlv_off, (void *)itlv, tlv_size);
	if (err)
		return err;

	// the following can't be moved inside update_tlv_pad because the
	// bpf verifier has some issues with it
	pad_off += sizeof(*itlv) + itlv->len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;

	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return __update_tlv_pad(skb, new_pad, pad_size, pad_off);
}

__attribute__((always_inline))
int seg6_delete_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh,
		    uint32_t tlv_off)
{
	uint32_t srh_off = (char *)srh - (char *)(long)skb->data;
	uint8_t len_remaining, new_pad;
	uint32_t partial_srh_len;
	uint32_t pad_off = 0;
	uint32_t pad_size = 0;
	struct sr6_tlv_t tlv;
	int err;

	tlv_off += srh_off;

	err = __is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err)
		return err;

	err = bpf_skb_load_bytes(skb, tlv_off, &tlv, sizeof(tlv));
	if (err)
		return err;

	err = bpf_lwt_seg6_adjust_srh(skb, tlv_off, -(sizeof(tlv) + tlv.len));
	if (err)
		return err;

	pad_off -= sizeof(tlv) + tlv.len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return __update_tlv_pad(skb, new_pad, pad_size, pad_off);
}

__attribute__((always_inline))
int seg6_find_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, unsigned char type,
		  unsigned char len)
{
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	// initial cursor = end of segments, start of possible TLVs
	int cursor = srh_offset + sizeof(struct ip6_srh_t) +
		((srh->first_segment + 1) << 4);

	#pragma clang loop unroll(full)
	for(int i=0; i < TLV_ITERATIONS; i++) {
		if (cursor >= srh_offset + ((srh->hdrlen + 1) << 3))
			return -1;

		struct sr6_tlv_t tlv;
		if (bpf_skb_load_bytes(skb, cursor, &tlv, sizeof(struct sr6_tlv_t)))
			return -1;
		//bpf_trace_printk("TLV type=%d len=%d found at offset %d\n", tlv.type, tlv.len, cursor);
	
		if (tlv.type == type && tlv.len + sizeof(struct sr6_tlv_t) == len)
			return cursor;

		cursor += sizeof(tlv) + tlv.len;
	}
	return -1;
}
