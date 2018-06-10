#!/bin/bash

BW_NORTH_UP=50
BW_NORTH_DOWN=50
BW_SOUTH_UP=50
BW_SOUTH_DOWN=150

LATENCY_NORTH_UP=15
LATENCY_NORTH_DOWN=10
LATENCY_SOUTH_UP=5
LATENCY_SOUTH_DOWN=20
JITTER_SOUTH=0
JITTER_NORTH=0
LOSS_NORTH="0.1%"
LOSS_SOUTH="0.1%"

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "selftests: test_lwt_seg6local [PASS]";
	else
		echo "selftests: test_lwt_seg6local [FAILED]";
	fi

	set +e
	pkill -F /tmp/link_aggreg_fc00::4-128.pid
	sleep 2
	ip netns del ns1 2> /dev/null
	ip netns del ns2 2> /dev/null
	ip netns del ns3 2> /dev/null
	ip netns del ns4 2> /dev/null
	ip netns del ns2N 2> /dev/null
	ip netns del ns2S 2> /dev/null
}

set -e
#set -x

ip netns add ns1
ip netns add ns2
ip netns add ns3
ip netns add ns4
ip netns add ns2N
ip netns add ns2S

trap cleanup 0 2 3 6 9

ip link add veth1 type veth peer name veth2
ip link add veth3 type veth peer name veth3-brW
ip link add veth3-brE type veth peer name simu-SW
ip link add veth4 type veth peer name simu-SE
ip link add veth5 type veth peer name veth6
ip link add veth7 type veth peer name veth7-brW
ip link add veth7-brE type veth peer name simu-NW
ip link add veth8 type veth peer name simu-NE

ip link set veth1 netns ns1
ip link set veth2 netns ns2
ip link set veth3 netns ns2
ip link set veth3-brW netns ns2
ip link set veth3-brE netns ns2
ip link set veth4 netns ns3
ip link set veth5 netns ns3
ip link set veth6 netns ns4
ip link set veth7 netns ns2
ip link set veth7-brW netns ns2
ip link set veth7-brE netns ns2
ip link set veth8 netns ns3

# For simulation purposes
ip link set simu-SW netns ns2S
ip link set simu-SE netns ns2S
ip link set simu-NW netns ns2N
ip link set simu-NE netns ns2N

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
ip netns exec ns2 ip link set dev veth3 up
ip netns exec ns2 ip link set dev veth3-brW up
ip netns exec ns2 ip link set dev veth3-brE up
ip netns exec ns3 ip link set dev veth4 up
ip netns exec ns3 ip link set dev veth5 up
ip netns exec ns4 ip link set dev veth6 up
ip netns exec ns2 ip link set dev veth7 up
ip netns exec ns2 ip link set dev veth7-brW up
ip netns exec ns2 ip link set dev veth7-brE up
ip netns exec ns3 ip link set dev veth8 up

ip netns exec ns2 ip link set dev lo up
ip netns exec ns3 ip link set dev lo up

# For simulation purposes
ip netns exec ns2S ip link set dev simu-SW up
ip netns exec ns2S ip link set dev simu-SE up
ip netns exec ns2N ip link set dev simu-NW up
ip netns exec ns2N ip link set dev simu-NE up

# This two bridges are part of the setup and are needed to insert compensation delay
# for trafic going back to ns1
ip netns exec ns2 ip link add name br3 type bridge
ip netns exec ns2 ip link set br3 up
ip netns exec ns2 ip link set veth3-brW master br3
ip netns exec ns2 ip link set veth3-brE master br3

ip netns exec ns2 ip link add name br7 type bridge
ip netns exec ns2 ip link set br7 up
ip netns exec ns2 ip link set veth7-brW master br7
ip netns exec ns2 ip link set veth7-brE master br7

# These two bridges are needed for simulation purposes, to add delays and losses between ns2 and ns3
ip netns exec ns2S ip link add name brS type bridge
ip netns exec ns2S ip link set brS up
ip netns exec ns2S ip link set simu-SW master brS
ip netns exec ns2S ip link set simu-SE master brS

ip netns exec ns2N ip link add name brN type bridge
ip netns exec ns2N ip link set brN up
ip netns exec ns2N ip link set simu-NW master brN
ip netns exec ns2N ip link set simu-NE master brN

# All link scope addresses and routes required between veths
ip netns exec ns1 ip -6 addr add fe80::12/10 dev veth1 scope link
ip netns exec ns1 ip -6 route add fe80::21 dev veth1 scope link
ip netns exec ns2 ip -6 addr add fe80::21/10 dev veth2 scope link
ip netns exec ns2 ip -6 route add fe80::12 dev veth2 scope link
ip netns exec ns2 ip -6 addr add fe80::34/10 dev veth3 scope link
ip netns exec ns2 ip -6 route add fe80::43 dev veth3 scope link
ip netns exec ns3 ip -6 route add fe80::65 dev veth5 scope link
ip netns exec ns3 ip -6 addr add fe80::43/10 dev veth4 scope link
ip netns exec ns3 ip -6 addr add fe80::56/10 dev veth5 scope link
ip netns exec ns3 ip -6 route add fe80::34 dev veth4 scope link
ip netns exec ns4 ip -6 addr add fe80::65/10 dev veth6 scope link
ip netns exec ns4 ip -6 route add fe80::56/10 dev veth6 scope link

ip netns exec ns2 ip -6 addr add fe80::78/10 dev veth7 scope link
ip netns exec ns2 ip -6 route add fe80::87 dev veth7 scope link
ip netns exec ns3 ip -6 addr add fe80::87/10 dev veth8 scope link
ip netns exec ns3 ip -6 route add fe80::78 dev veth8 scope link

ip netns exec ns1 ip -6 addr add fc00::1/16 dev lo
ip netns exec ns2 ip -6 addr add fc00::2/16 dev lo
ip netns exec ns2 ip -6 addr add fc00::2a/16 dev lo
ip netns exec ns2 ip -6 addr add fc00::2b/16 dev lo
ip netns exec ns3 ip -6 addr add fc00::3/16 dev lo
ip netns exec ns3 ip -6 addr add fc00::3a/16 dev lo
ip netns exec ns3 ip -6 addr add fc00::3b/16 dev lo
ip netns exec ns4 ip -6 addr add fc00::4/16 dev lo

ip netns exec ns1 ip -6 route add fc00::4 dev veth1 via fe80::21
ip netns exec ns4 ip -6 route add fc00::1 dev veth6 via fe80::56

ip netns exec ns2 ip sr tunsrc set fc00::2
ip netns exec ns2 ip -6 route add fc00::1 dev veth2 via fe80::12
#ip netns exec ns2 ip -6 route add fc00::4 dev veth3 via fe80::43
#ip netns exec ns2 ip -6 route add fc00::4 encap seg6 mode encap segs fc00::3b dev veth3
ip netns exec ns2 ip -6 route add fc00::3 dev veth3 via fe80::43
ip netns exec ns2 ip -6 route add fc00::3a dev veth3 via fe80::43
ip netns exec ns2 ip -6 route add fc00::3b dev veth7 via fe80::87

ip netns exec ns3 ip sr tunsrc set fc00::3
ip netns exec ns3 ip -6 route add fc00::4 dev veth5 via fe80::65
#ip netns exec ns3 ip -6 route add fc00::1 dev veth4 via fe80::34
ip netns exec ns3 ip -6 route add fc00::2 dev veth4 via fe80::34
ip netns exec ns3 ip -6 route add fc00::2a dev veth4 via fe80::34
ip netns exec ns3 ip -6 route add fc00::2b dev veth8 via fe80::78
ip netns exec ns3 ip -6 route add fc00::2c dev veth4 via fe80::34

set +e
rm /sys/fs/bpf/ip/globals/end_otp_delta
rm /sys/fs/bpf/ip/globals/uplink_wrr_sids
rm /sys/fs/bpf/ip/globals/uplink_wrr_weights
rm /sys/fs/bpf/ip/globals/uplink_wrr_state
set -e

./netns.py ns3 sysctl net.core.bpf_jit_enable=2

./netns.py ns3 /home/math/shared/iproute2/ip/ip -6 route add fc00::3c encap seg6local action End.BPF obj cpe_bpf/end_otp_bpf.o section end_otp dev veth4
./netns.py ns3 cpe_bpf/end_otp_usr

./netns.py ns3 /home/math/shared/iproute2/ip/ip -6 route add fc00::1 encap bpf in obj cpe_bpf/uplink_wrr_bpf.o section main dev veth4
./netns.py ns3 cpe_bpf/uplink_wrr_usr fc00::2 fc00::2a ${BW_SOUTH_UP} fc00::2b ${BW_NORTH_UP}

ip netns exec ns2S tc qdisc add dev simu-SE handle 1: root htb default 11
ip netns exec ns2S tc class add dev simu-SE parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2S tc class add dev simu-SE parent 1:1 classid 1:11 htb rate ${BW_SOUTH_DOWN}Mbit
ip netns exec ns2S tc qdisc add dev simu-SE parent 1:11 handle 10: netem delay ${LATENCY_SOUTH_DOWN}ms ${JITTER_SOUTH}ms
#ip netns exec ns2S tc qdisc add dev simu-SE parent 2:11 handle 11: netem loss ${LOSS_SOUTH}

ip netns exec ns2S tc qdisc add dev simu-SW handle 1: root htb default 11
ip netns exec ns2S tc class add dev simu-SW parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2S tc class add dev simu-SW parent 1:1 classid 1:11 htb rate ${BW_SOUTH_UP}Mbit
ip netns exec ns2S tc qdisc add dev simu-SW parent 1:11 handle 10: netem delay ${LATENCY_SOUTH_UP}ms ${JITTER_SOUTH}ms
#ip netns exec ns2S tc qdisc add dev simu-SW parent 2:11 handle 11: netem loss ${LOSS_SOUTH}

ip netns exec ns2N tc qdisc add dev simu-NE handle 2: root htb default 11
ip netns exec ns2N tc class add dev simu-NE parent 2: classid 2:1 htb rate 1000Mbps
ip netns exec ns2N tc class add dev simu-NE parent 2:1 classid 2:11 htb rate ${BW_NORTH_DOWN}Mbit
ip netns exec ns2N tc qdisc add dev simu-NE parent 2:11 handle 10: netem delay ${LATENCY_NORTH_DOWN}ms ${JITTER_NORTH}ms
#ip netns exec ns2N tc qdisc add dev simu-NE parent 2:11 handle 11: netem loss ${LOSS_NORTH}

ip netns exec ns2N tc qdisc add dev simu-NW handle 2: root htb default 11
ip netns exec ns2N tc class add dev simu-NW parent 2: classid 2:1 htb rate 1000Mbps
ip netns exec ns2N tc class add dev simu-NW parent 2:1 classid 2:11 htb rate ${BW_NORTH_UP}Mbit
ip netns exec ns2N tc qdisc add dev simu-NW parent 2:11 handle 10: netem delay ${LATENCY_NORTH_UP}ms ${JITTER_NORTH}ms
#ip netns exec ns2N tc qdisc add dev simu-NW parent 2:11 handle 11: netem loss ${LOSS_NORTH}

ip netns exec ns2 sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns2N sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns2S sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.all.forwarding=1 > /dev/null

ip netns exec ns2 sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.veth3.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.veth7.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.veth2.seg6_enabled=1 > /dev/null

ip netns exec ns3 sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth4.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth8.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth5.seg6_enabled=1 > /dev/null

sleep 3
ip netns exec ns2 tc qdisc add dev veth3 root handle 1: htb default 42 # default non-classified traffic goes to 1:12
ip netns exec ns2 tc class add dev veth3 parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc filter add dev veth3 protocol all parent 1: prio 2 u32 match u32 0 0 flowid 1:1
ip netns exec ns2 tc qdisc add dev veth3 parent 1:1 handle 20: sfq

ip netns exec ns2 tc qdisc add dev veth3-brW root handle 1: htb default 42 # default non-classified traffic goes to 1:12
ip netns exec ns2 tc class add dev veth3-brW parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc filter add dev veth3-brW protocol all parent 1: prio 2 u32 match u32 0 0 flowid 1:1
ip netns exec ns2 tc qdisc add dev veth3-brW parent 1:1 handle 20: sfq

ip netns exec ns2 tc qdisc add dev veth7 root handle 1: htb default 42 # default non-classified traffic goes to 1:12
ip netns exec ns2 tc class add dev veth7 parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc filter add dev veth7 protocol all parent 1: prio 2 u32 match u32 0 0 flowid 1:1
ip netns exec ns2 tc qdisc add dev veth7 parent 1:1 handle 20: sfq

ip netns exec ns2 tc qdisc add dev veth7-brW root handle 1: htb default 42 # default non-classified traffic goes to 1:12
ip netns exec ns2 tc class add dev veth7-brW parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc filter add dev veth7-brW protocol all parent 1: prio 2 u32 match u32 0 0 flowid 1:1
ip netns exec ns2 tc qdisc add dev veth7-brW parent 1:1 handle 20: sfq

ip netns exec ns2 ./link_aggreg.py fc00::4/128 fc00::3 fc00::3a fc00::2a $BW_SOUTH_DOWN fc00::3b fc00::2b $BW_NORTH_DOWN fc00::3c fc00::2c veth3,veth7 veth3-brW,veth7-brW

sleep 1

ip netns exec ns2 /home/math/shared/iproute2/ip/ip -6 route
ip netns exec ns2 /home/math/shared/iproute2/ip/ip -6 link
ip netns exec ns3 /home/math/shared/iproute2/ip/ip -6 route
#for latency in {10..100..10}
#for jitter in $(seq 0 $JITTER_NORTH);
#do
	#echo "NEW LATENCY: ${latency}"
	#ip netns exec ns2S tc qdisc change dev veth4-br parent 1:11 handle 10: netem delay ${latency}ms

	#echo "NEW JITTER: ${jitter}ms"
	#ip netns exec ns2N tc qdisc change dev veth8-br parent 2:11 handle 10: netem delay ${LATENCY_NORTH_DOWN}ms ${jitter}ms

	#for i in {0..0}
	#do
		ip netns exec ns1 ping -c 5 -I fc00::1 fc00::4

		#ip netns exec ns4 iperf -s -V -D
		#sleep 1
		#ip netns exec ns1 iperf -V -t 10 -l 1350 -M 1350 -B fc00::1 -c fc00::4 -e
		#killall iperf

		#ip netns exec ns1 iperf -s -V -D
		#sleep 1
		#ip netns exec ns4 iperf -V -t 10 -l 1350 -M 1350 -B fc00::4 -c fc00::1 -e
		#killall iperf

	#done

#done
exit 0
