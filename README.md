# Thesis-SRv6-BPF
Code written for my master's thesis on End.BPF, an interface for programmable IPv6 Segment Routing network functions, and also featured in the paper _"Leveraging eBPF for programmable network functions with IPv6 Segment Routing"_, presented at CoNext 2018. The full thesis manuscript, including the architecture and performance evaluations of End.BPF and of the three use-cases released in this repository, is available in [Thesis.pdf](Thesis.pdf).

The Linux patches adding the End.BPF hook and the four SRv6-related helpers can be retrieved from [net-next's patchwork website](https://patchwork.ozlabs.org/project/netdev/list/?series=&submitter=73189&state=3&q=&archive=&delegate=). These modifications are available in the upstream Linux kernel since Linux 4.18 (August 2018).

Instructions for replicating the results presented in the CoNext 2018 paper are available [here](CoNext-replication.md).

This repository contains:

- segway: a unit testing framework for SRv6
- libseg6: a library for handling IPv6 Segment Routing Headers in BPF
- use-cases: the code, scripts and Makefiles of the use-cases developed in my master's thesis, that rely on SRv6 BPF
- linux-seg6-bpf: linux kernel with the modifications required by the above use-cases
- openwrt-seg6: fork of OpenWRT/LEDE with a SRv6 BPF support for Linux 4.14
