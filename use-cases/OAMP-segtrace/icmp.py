import socket, struct, sys

def calculate_checksum(source_string):
    #Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    #Distributable under the terms of the GNU General Public License
    #version 2. Provided with no warranties of any sort.

    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
            if (sys.byteorder == "little"):
                    loByte = source_string[count]
                    hiByte = source_string[count + 1]
            else:
                    loByte = source_string[count + 1]
                    hiByte = source_string[count]

            sum = sum + (hiByte * 256 + loByte)
            count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string): # Check for odd length
            loByte = source_string[len(source_string) - 1]
            sum += loByte

    sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                                      # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)	# Add high 16 bits to low 16 bits
    sum += (sum >> 16)					# Add carry from above (if any)
    answer = ~sum & 0xffff				# Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

def send(src, dst, type, code, data, hops=64, srh=None):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hops)
    if srh:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, srh)

    sock.bind((src, 1))

    # Compute ICMPv6 pseudo header
    pseudo_header = socket.inet_pton(socket.AF_INET6, src)
    pseudo_header += socket.inet_pton(socket.AF_INET6, dst)
    pseudo_header += struct.pack("!IBBBBBBH", len(data)+4, 0, 0, 0, 58, type, code, 0)
    checksum = calculate_checksum(pseudo_header + data)

    header = struct.pack("!BBH", type, code, checksum)
    packet = header + data
    sock.sendto(packet, (dst, 0)) # Port number is irrelevant for ICMP


if __name__ == '__main__':
    data = "075c0001"
    data = bytearray.fromhex(data)
    send("2a02:a03f:4258:3200:7ce:57d4:ce01:d90f", "2a00:1450:400e:802::200e", 128, 0, data)
