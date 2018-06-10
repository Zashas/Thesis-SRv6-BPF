# Thesis-SRv6-BPF
Code written for my master's thesis on End.BPF, an interface for programmable IPv6 Segment Routing network functions.

This repository contains:

- segway: a unit testing framework for SRv6
- libseg6: a library for handling IPv6 Segment Routing Headers in BPF
- use-cases: the code of the use-cases developed in my master's thesis, that rely on SRv6 BPF
- linux-seg6-bpf: linux kernel with the modifications required by the above use-cases
- openwrt-seg6: fork of OpenWRT/LEDE with a SRv6 BPF support for Linux 4.14
