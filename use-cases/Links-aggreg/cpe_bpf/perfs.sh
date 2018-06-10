#!/bin/bash

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "End.OTP perfs [PASS]";
	else
		echo "End.OTP perfs [FAILED]";
	fi

	set +e
	#rm inject_dm
	ip netns del ns1 2> /dev/null
	ip netns del ns2 2> /dev/null
	pkill -F /tmp/end_otp_fb00::3-128.pid
}

set -e
trap cleanup 0 2 3 6 9

#gcc measures/inject_dm.c -o inject_dm

ip netns add ns1
ip netns add ns2

ip link add veth1 type veth peer name veth2

ip link set veth1 netns ns1
ip link set veth2 netns ns2

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
ip netns exec ns1 ip link set dev lo up
ip netns exec ns2 ip link set dev lo up

# All link scope addresses and routes required between veths
ip netns exec ns1 ip -6 addr add fb00::12/16 dev veth1
ip netns exec ns1 ip -6 route add fb00::21 dev veth1
ip netns exec ns2 ip -6 addr add fb00::21/16 dev veth2
ip netns exec ns2 ip -6 route add fb00::12/16 dev veth2

ip netns exec ns1 ip -6 addr add fb00::1 dev lo
ip netns exec ns2 ip -6 addr add fb00::2 dev lo

ip netns exec ns1 tc qdisc add dev veth1 root netem delay 1ms

ip netns exec ns2 ./end_otp.py fb00::3/128 veth2
ip netns exec ns1 ip -6 route add fb00::3 via fb00::21 dev veth1
ip netns exec ns1 ip -6 route add fb00::2 via fb00::21 dev veth1
ip netns exec ns2 ip -6 route add fb00::1 via fb00::12 dev veth2

# needed so fb00::1 and fb00::2 both have the other MAC address in cache
# otherwise the first measurement is flawed
ip netns exec ns1 ping -I fb00::1 fb00::2 -c 1 > /dev/null

read -p "Press enter to start measuring"
ip netns exec ns1 bash -c "measures/recv.py &"
sleep 1
for i in {0..4}
  do
     delay="$((10 ** $i))"
     delay="$(($delay / 10))"
     ip netns exec ns1 tc qdisc change dev veth1 root netem delay ${delay}ms
     echo "delay: $delay"
     for j in {1..20}
     do
        ip netns exec ns1 ./inject_dm fb00::1 fb00::2 9000 fb00::3
        sleep 1
     done
 done

exit 0
