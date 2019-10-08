import socket
import sys


# You'll have to construct this, but it can be the same for every ping you send
PING_PAYLOAD = (0x0800db2a0e200001fb78635a00000000e70d0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637).to_bytes(64, 'big')


def trace(target, max_hops=64):
    """
    Trace the route to target by sending pings with incrementally larger TTL.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(3)

    for ttl in range(1, max_hops):
        s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        s.sendto(PING_PAYLOAD, (target,  7))

        try:
            payload, (host, _) = s.recvfrom(4096)
        except socket.timeout as e:
            print('Timeout on ttl: {}'.format(ttl))
            continue
        
        print(host)
        if host == target:
            break


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 traceroute.py [ip address]')
        sys.exit(1)

    target = sys.argv[1]
    trace(target)
