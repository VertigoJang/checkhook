"""Which source addresses detectors may never block."""
import ipaddress

RFC1918 = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def should_skip(s, block_private=False):
    """True for anything that must not be blocked: non-IPv4, loopback,
    link-local, multicast, unspecified, and (unless block_private) RFC1918."""
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return True
    if ip.version != 4:
        return True
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if any(ip in net for net in RFC1918) and not block_private:
        return True
    return False
