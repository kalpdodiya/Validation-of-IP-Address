"""
validator.py - Computer Networks IP Address Validation & Subnet Analysis Engine
Uses Python's standard `ipaddress` module and network fundamentals for:
- IPv4 validation, classful addressing (A-E), RFC 1918 private check, CIDR, binary octets
- IPv6 validation, expansion, compression, address classification, scopes, 16-bit hex groups
- CIDR Subnet Calculator for IPv4 and IPv6
"""

import ipaddress
import math
import re


def to_binary_8(num: int) -> str:
    """Format an integer (0-255) as an 8-bit binary string."""
    return format(num, '08b')


def to_binary_16(num: int) -> str:
    """Format an integer (0-65535) as a 16-bit binary string."""
    return format(num, '016b')


def get_ipv4_class_info(first_octet: int):
    """
    Determine IPv4 class, default subnet mask, CIDR prefix, network/host bits,
    and class range based on standard Computer Networks classful addressing.
    """
    if 1 <= first_octet <= 126:
        return {
            'class': 'A',
            'range': '1.0.0.0 - 126.255.255.255',
            'leading': '0',
            'defaultSubnet': '255.0.0.0',
            'cidrPrefix': 8,
            'networkBits': 8,
            'hostBits': 24
        }
    elif first_octet == 127:
        return {
            'class': 'Loopback',
            'range': '127.0.0.0 - 127.255.255.255',
            'leading': '01111111',
            'defaultSubnet': '255.0.0.0',
            'cidrPrefix': 8,
            'networkBits': 8,
            'hostBits': 24
        }
    elif 128 <= first_octet <= 191:
        return {
            'class': 'B',
            'range': '128.0.0.0 - 191.255.255.255',
            'leading': '10',
            'defaultSubnet': '255.255.0.0',
            'cidrPrefix': 16,
            'networkBits': 16,
            'hostBits': 16
        }
    elif 192 <= first_octet <= 223:
        return {
            'class': 'C',
            'range': '192.0.0.0 - 223.255.255.255',
            'leading': '110',
            'defaultSubnet': '255.255.255.0',
            'cidrPrefix': 24,
            'networkBits': 24,
            'hostBits': 8
        }
    elif 224 <= first_octet <= 239:
        return {
            'class': 'D (Multicast)',
            'range': '224.0.0.0 - 239.255.255.255',
            'leading': '1110',
            'defaultSubnet': 'N/A',
            'cidrPrefix': 0,
            'networkBits': 0,
            'hostBits': 0
        }
    elif 240 <= first_octet <= 255:
        return {
            'class': 'E (Reserved/Experimental)',
            'range': '240.0.0.0 - 255.255.255.255',
            'leading': '1111',
            'defaultSubnet': 'N/A',
            'cidrPrefix': 0,
            'networkBits': 0,
            'hostBits': 0
        }
    else:  # 0.x.x.x
        return {
            'class': 'Current Network (0.0.0.0/8)',
            'range': '0.0.0.0 – 0.255.255.255',
            'leading': '0',
            'defaultSubnet': '255.0.0.0',
            'cidrPrefix': 8,
            'networkBits': 8,
            'hostBits': 24
        }


def validate_ipv4(ip_str: str) -> dict:
    """Validate and thoroughly analyze an IPv4 address."""
    clean_ip = ip_str.strip()

    # Syntax verification
    parts = clean_ip.split('.')
    if len(parts) != 4:
        return {
            'valid': False,
            'error': f'Invalid IPv4 format: Expected 4 octets separated by dots (e.g. 192.168.1.1), got {len(parts)}.'
        }

    octets = []
    for i, p in enumerate(parts):
        if not p.isdigit() or (len(p) > 1 and p.startswith('0')):
            # Check for invalid characters or leading zeroes
            if not p.isdigit():
                return {'valid': False, 'error': f'Octet {i + 1} ("{p}") contains non-numeric characters.'}
            # allow 0 but not 01 or 001
            return {'valid': False, 'error': f'Octet {i + 1} ("{p}") contains invalid leading zeros.'}
        val = int(p)
        if val < 0 or val > 255:
            return {'valid': False, 'error': f'Octet {i + 1} ({val}) is out of range [0–255].'}
        octets.append(val)

    try:
        addr = ipaddress.IPv4Address(clean_ip)
    except Exception as e:
        return {'valid': False, 'error': f'Invalid IPv4 address: {str(e)}'}

    binary_octets = [to_binary_8(o) for o in octets]
    binary_full = '.'.join(binary_octets)

    # Classful classification
    cls_info = get_ipv4_class_info(octets[0])
    ip_class = cls_info['class']
    class_range = cls_info['range']
    leading_bits = cls_info['leading']
    default_subnet = cls_info['defaultSubnet']
    cidr_prefix = cls_info['cidrPrefix']
    network_bits = cls_info['networkBits']
    host_bits = cls_info['hostBits']

    max_hosts = (2 ** host_bits - 2) if host_bits > 0 else 0

    # RFC 1918 Private ranges check
    is_private = addr.is_private
    private_range = 'N/A'
    if octets[0] == 10:
        is_private = True
        private_range = '10.0.0.0/8'
    elif octets[0] == 172 and 16 <= octets[1] <= 31:
        is_private = True
        private_range = '172.16.0.0/12'
    elif octets[0] == 192 and octets[1] == 168:
        is_private = True
        private_range = '192.168.0.0/16'

    is_loopback = addr.is_loopback or octets[0] == 127
    is_broadcast = clean_ip == '255.255.255.255'
    is_link_local = addr.is_link_local or (octets[0] == 169 and octets[1] == 254)
    is_multicast = addr.is_multicast or (224 <= octets[0] <= 239)
    is_reserved = addr.is_reserved or (240 <= octets[0] <= 255)

    is_public = (not is_private and not is_loopback and not is_broadcast
                 and not is_link_local and not is_multicast and not is_reserved and octets[0] != 0)

    # Special purpose label
    if is_loopback:
        special_type = 'Loopback'
    elif is_broadcast:
        special_type = 'Broadcast'
    elif is_link_local:
        special_type = 'APIPA / Link-Local'
    elif is_private:
        special_type = 'Private'
    elif is_multicast:
        special_type = 'Multicast'
    elif is_reserved:
        special_type = 'Reserved'
    else:
        special_type = 'Public'

    # Network, Broadcast, First and Last usable host for classful default
    network_address = 'N/A'
    broadcast_address = 'N/A'
    first_host = 'N/A'
    last_host = 'N/A'

    if ip_class == 'A':
        network_address = f"{octets[0]}.0.0.0"
        broadcast_address = f"{octets[0]}.255.255.255"
        first_host = f"{octets[0]}.0.0.1"
        last_host = f"{octets[0]}.255.255.254"
    elif ip_class == 'B':
        network_address = f"{octets[0]}.{octets[1]}.0.0"
        broadcast_address = f"{octets[0]}.{octets[1]}.255.255"
        first_host = f"{octets[0]}.{octets[1]}.0.1"
        last_host = f"{octets[0]}.{octets[1]}.255.254"
    elif ip_class == 'C':
        network_address = f"{octets[0]}.{octets[1]}.{octets[2]}.0"
        broadcast_address = f"{octets[0]}.{octets[1]}.{octets[2]}.255"
        first_host = f"{octets[0]}.{octets[1]}.{octets[2]}.1"
        last_host = f"{octets[0]}.{octets[1]}.{octets[2]}.254"

    return {
        'valid': True,
        'version': 'IPv4',
        'ip': clean_ip,
        'octets': octets,
        'binaryOctets': binary_octets,
        'binaryRepresentation': binary_full,
        'ipClass': ip_class,
        'classRange': class_range,
        'leadingBits': leading_bits,
        'defaultSubnet': default_subnet,
        'cidrNotation': f"{clean_ip}/{cidr_prefix}" if cidr_prefix > 0 else 'N/A',
        'networkBits': network_bits,
        'hostBits': host_bits,
        'maxHosts': max_hosts,
        'networkAddress': network_address,
        'broadcastAddress': broadcast_address,
        'firstUsableHost': first_host,
        'lastUsableHost': last_host,
        'isPrivate': is_private,
        'privateRange': private_range,
        'isLoopback': is_loopback,
        'loopback': 'Yes' if is_loopback else 'No',
        'isBroadcast': is_broadcast,
        'isLinkLocal': is_link_local,
        'isMulticast': is_multicast,
        'isPublic': is_public,
        'publicOrPrivate': 'Public' if is_public else ('Private' if is_private else special_type),
        'numberOfAddresses': f"{max_hosts:,} usable ({(2**host_bits) if host_bits > 0 else 0:,} total)",
        'specialType': special_type
    }


def expand_ipv6(ip_str: str) -> tuple[str, list[str]]:
    """
    Expand an IPv6 address into full 8 groups of 4 hexadecimal characters.
    Handles standard IPv6 as well as IPv4-mapped IPv6 (::ffff:192.0.2.1).
    """
    clean_ip = ip_str.strip()

    # Check for IPv4-mapped notation like ::ffff:192.0.2.1
    ipv4_mapped_match = re.search(r'^(.*:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', clean_ip)
    if ipv4_mapped_match:
        # Keep exact visual matching with reference prototype
        if '::' in clean_ip:
            left, right = clean_ip.split('::', 1)
            left_parts = [p for p in left.split(':') if p]
            right_parts = [p for p in right.split(':') if p]
            total_explicit = len(left_parts) + len(right_parts)
            zeros_needed = 8 - total_explicit
            mid = ['0000'] * zeros_needed
            raw_groups = [p.zfill(4) if not '.' in p else p for p in left_parts] + mid + [p.zfill(4) if not '.' in p else p for p in right_parts]
            expanded = ':'.join(raw_groups)
            return expanded, raw_groups
        else:
            raw_groups = clean_ip.split(':')
            raw_groups = [p.zfill(4) if not '.' in p else p for p in raw_groups]
            return ':'.join(raw_groups), raw_groups

    # Pure IPv6
    addr = ipaddress.IPv6Address(clean_ip)
    exploded = addr.exploded
    groups = exploded.split(':')
    return exploded, groups


def validate_ipv6(ip_str: str) -> dict:
    """Validate and thoroughly analyze an IPv6 address."""
    clean_ip = ip_str.strip()

    if clean_ip.count('::') > 1:
        return {'valid': False, 'error': 'Invalid IPv6 format: address cannot contain more than one "::".'}

    try:
        addr = ipaddress.IPv6Address(clean_ip)
    except Exception as e:
        return {'valid': False, 'error': f'Invalid IPv6 format: {str(e)}.'}

    expanded, groups = expand_ipv6(clean_ip)

    # Calculate 16-bit binary groups and full 128-bit binary representation
    binary_groups = []
    for g in groups:
        if '.' in g:
            # Handles IPv4-mapped notation like '192.0.2.1' matching reference visual breakdown
            try:
                prefix_hex = g.split('.')[0]
                val = int(prefix_hex, 16)
                binary_groups.append(to_binary_16(val))
            except Exception:
                binary_groups.append('0' * 16)
        else:
            try:
                val = int(g, 16)
                binary_groups.append(to_binary_16(val))
            except ValueError:
                binary_groups.append('0' * 16)

    # Ensure binary_groups has 8 entries
    if len(binary_groups) > 8:
        binary_groups = binary_groups[:8]
    while len(binary_groups) < 8:
        binary_groups.append('0' * 16)

    binary_full = ':'.join(binary_groups)

    # Address Type & Scope determination matching standard CN curriculum and screenshots
    address_type = 'Global Unicast'
    scope = 'Global'

    g0 = groups[0].lower() if groups else ''

    if clean_ip == '::1' or expanded == '0000:0000:0000:0000:0000:0000:0000:0001':
        address_type = 'Loopback'
        scope = 'Node'
    elif clean_ip == '::' or expanded == '0000:0000:0000:0000:0000:0000:0000:0000':
        address_type = 'Unspecified'
        scope = 'None'
    elif g0.startswith('fe8') or g0.startswith('fe9') or g0.startswith('fea') or g0.startswith('feb'):
        address_type = 'Link-Local Unicast'
        scope = 'Link'
    elif g0.startswith('fc') or g0.startswith('fd'):
        address_type = 'Unique Local Unicast (ULA)'
        scope = 'Organization/Site'
    elif g0.startswith('ff'):
        address_type = 'Multicast'
        # multicast scope flags: ff01 (node), ff02 (link), ff05 (site), ff08 (org), ff0e (global)
        if len(g0) >= 4:
            sc_char = g0[3]
            scope_map = {'1': 'Node', '2': 'Link', '5': 'Site', '8': 'Organization/Site', 'e': 'Global'}
            scope = scope_map.get(sc_char, 'Varies')
        else:
            scope = 'Varies'
    elif len(groups) >= 8 and groups[0] == '0000' and groups[1] == '0000' and groups[2] == '0000' and groups[3] == '0000' and groups[4] == '0000' and groups[5].lower() == 'ffff':
        address_type = 'IPv4-Mapped IPv6'
        scope = 'Global'
    elif groups[0] == '2002':
        address_type = '6to4 Tunneling'
        scope = 'Global'
    elif groups[0] == '2001' and len(groups) > 1 and groups[1] == '0000':
        address_type = 'Teredo Tunneling'
        scope = 'Global'
    elif groups[0] == '2001' and len(groups) > 1 and groups[1].lower() == '0db8':
        address_type = 'Documentation'
        scope = 'Global'

    # Special case for IPv4-mapped visual reference in screenshot (78)
    if '::ffff:' in clean_ip and '.' in clean_ip:
        address_type = 'Global Unicast'
        scope = 'Global'

    is_compressed = '::' in clean_ip

    # IPv6 Network calculations (/64 typical prefix)
    try:
        net6 = ipaddress.IPv6Network(f"{clean_ip}/64", strict=False)
        network_address_v6 = str(net6.network_address)
        num_addresses_v6 = f"{net6.num_addresses:,}"
    except Exception:
        network_address_v6 = clean_ip
        num_addresses_v6 = f"{2**64:,}"

    is_loopback_v6 = addr.is_loopback or clean_ip == '::1'
    if clean_ip.lower().startswith('fc') or clean_ip.lower().startswith('fd') or address_type.startswith('Unique Local'):
        is_private_v6 = True
        is_public_v6 = False
        public_or_private_v6 = 'Private (ULA)'
    elif is_loopback_v6:
        is_private_v6 = False
        is_public_v6 = False
        public_or_private_v6 = 'Loopback'
    elif addr.is_link_local or clean_ip.lower().startswith('fe8') or clean_ip.lower().startswith('fe9') or clean_ip.lower().startswith('fea') or clean_ip.lower().startswith('feb'):
        is_private_v6 = False
        is_public_v6 = False
        public_or_private_v6 = 'Link-Local'
    elif addr.is_multicast or clean_ip.lower().startswith('ff'):
        is_private_v6 = False
        is_public_v6 = False
        public_or_private_v6 = 'Multicast'
    else:
        is_private_v6 = False
        is_public_v6 = True
        public_or_private_v6 = 'Public'

    return {
        'valid': True,
        'version': 'IPv6',
        'ip': clean_ip,
        'expanded': expanded,
        'groups': groups,
        'binaryGroups': binary_groups,
        'binaryRepresentation': binary_full,
        'addressType': address_type,
        'publicOrPrivate': public_or_private_v6,
        'networkAddress': network_address_v6,
        'numberOfAddresses': num_addresses_v6,
        'loopback': 'Yes' if is_loopback_v6 else 'No',
        'isLoopback': is_loopback_v6,
        'isPrivate': is_private_v6,
        'isPublic': is_public_v6,
        'scope': scope,
        'totalBits': 128,
        'groupCount': len(groups),
        'bitsPerGroup': 16,
        'prefixLength': '/64',
        'isCompressed': is_compressed
    }


def validate_ip(ip_str: str) -> dict:
    """Universal IP validation entry point: delegates to IPv4 or IPv6."""
    if not ip_str or not isinstance(ip_str, str):
        return {'valid': False, 'error': 'Please provide an IP address string.'}

    trimmed = ip_str.strip()
    if not trimmed:
        return {'valid': False, 'error': 'IP address input cannot be empty.'}

    if ':' in trimmed:
        return validate_ipv6(trimmed)
    return validate_ipv4(trimmed)


def calculate_subnet(cidr_str: str) -> dict:
    """
    Subnet Calculator for CIDR notation (e.g. 192.168.1.0/26 or 2001:db8::/64).
    Calculates subnet mask, wildcard mask, network address, broadcast address,
    first and last usable host, total/usable host counts, and bit breakdown.
    """
    if not cidr_str or not isinstance(cidr_str, str):
        return {'valid': False, 'error': 'Please provide CIDR notation (e.g. 192.168.1.0/24).'}

    clean_cidr = cidr_str.strip()
    if '/' not in clean_cidr:
        # Default prefix if omitted
        if ':' in clean_cidr:
            clean_cidr += '/64'
        else:
            clean_cidr += '/24'

    parts = clean_cidr.split('/')
    if len(parts) != 2:
        return {'valid': False, 'error': 'Invalid CIDR format. Expected format: IP/Prefix (e.g. 192.168.1.0/24).'}

    ip_part, prefix_str = parts[0].strip(), parts[1].strip()
    if not prefix_str.isdigit():
        return {'valid': False, 'error': 'Prefix length must be a non-negative integer.'}

    prefix = int(prefix_str)

    # IPv6 subnet calculation
    if ':' in ip_part:
        if prefix < 0 or prefix > 128:
            return {'valid': False, 'error': 'IPv6 prefix length must be between 0 and 128.'}
        try:
            net6 = ipaddress.IPv6Network(f"{ip_part}/{prefix}", strict=False)
        except Exception as e:
            return {'valid': False, 'error': f'Invalid IPv6 CIDR: {str(e)}'}

        num_addresses = net6.num_addresses
        network_address = str(net6.network_address)
        last_address = str(ipaddress.IPv6Address(int(net6.network_address) + num_addresses - 1))

        return {
            'valid': True,
            'version': 'IPv6',
            'input': clean_cidr,
            'ip': ip_part,
            'prefix': prefix,
            'networkAddress': network_address,
            'broadcastAddress': last_address,
            'firstHost': network_address,
            'lastHost': last_address,
            'totalAddresses': num_addresses,
            'usableHosts': num_addresses,
            'networkBits': prefix,
            'hostBits': 128 - prefix,
            'isIPv6': True
        }

    # IPv4 subnet calculation
    if prefix < 0 or prefix > 32:
        return {'valid': False, 'error': 'IPv4 prefix length must be between 0 and 32.'}

    # Verify IP octets
    oct_parts = ip_part.split('.')
    if len(oct_parts) != 4:
        return {'valid': False, 'error': 'Invalid IPv4 address in CIDR. Expected 4 octets (e.g. 192.168.1.0).'}

    try:
        net = ipaddress.IPv4Network(f"{ip_part}/{prefix}", strict=False)
        ip_addr = ipaddress.IPv4Address(ip_part)
    except Exception as e:
        return {'valid': False, 'error': f'Invalid IPv4 CIDR: {str(e)}'}

    octets = [int(x) for x in str(ip_addr).split('.')]
    net_octets = [int(x) for x in str(net.network_address).split('.')]
    mask_octets = [int(x) for x in str(net.netmask).split('.')]
    bcast_octets = [int(x) for x in str(net.broadcast_address).split('.')]

    subnet_mask = str(net.netmask)
    wildcard_mask = str(net.hostmask)
    network_address = str(net.network_address)
    broadcast_address = str(net.broadcast_address)
    total_addresses = net.num_addresses

    if prefix <= 30:
        usable_hosts = total_addresses - 2
        first_host = str(ipaddress.IPv4Address(int(net.network_address) + 1))
        last_host = str(ipaddress.IPv4Address(int(net.broadcast_address) - 1))
    elif prefix == 31:
        # RFC 3021 Point-to-point links
        usable_hosts = 2
        first_host = network_address
        last_host = broadcast_address
    else:  # /32
        usable_hosts = 1
        first_host = network_address
        last_host = network_address

    ip_binary = '.'.join([to_binary_8(o) for o in octets])
    mask_binary = '.'.join([to_binary_8(o) for o in mask_octets])
    net_binary = '.'.join([to_binary_8(o) for o in net_octets])
    bcast_binary = '.'.join([to_binary_8(o) for o in bcast_octets])

    # Classful default comparison for borrowed bits & subnets
    classful_prefix = 24
    if 1 <= octets[0] <= 126:
        classful_prefix = 8
    elif 128 <= octets[0] <= 191:
        classful_prefix = 16
    elif 192 <= octets[0] <= 223:
        classful_prefix = 24

    borrowed_bits = max(0, prefix - classful_prefix)
    possible_subnets = 2 ** borrowed_bits if borrowed_bits > 0 else 1

    return {
        'valid': True,
        'version': 'IPv4',
        'input': clean_cidr,
        'ip': str(ip_addr),
        'prefix': prefix,
        'subnetMask': subnet_mask,
        'wildcardMask': wildcard_mask,
        'networkAddress': network_address,
        'broadcastAddress': broadcast_address,
        'firstHost': first_host,
        'lastHost': last_host,
        'totalAddresses': total_addresses,
        'usableHosts': usable_hosts,
        'networkBits': prefix,
        'hostBits': 32 - prefix,
        'ipBinary': ip_binary,
        'maskBinary': mask_binary,
        'networkBinary': net_binary,
        'broadcastBinary': bcast_binary,
        'classfulPrefix': classful_prefix,
        'borrowedBits': borrowed_bits,
        'possibleSubnets': possible_subnets,
        'maskOctets': mask_octets,
        'networkOctets': net_octets,
        'broadcastOctets': bcast_octets,
        'isIPv6': False
    }


if __name__ == '__main__':
    import sys
    test_input = sys.argv[1] if len(sys.argv) > 1 else '10.0.0.1'
    print(f"\n" + "=" * 54)
    print(f"  Testing validation for: {test_input}")
    print("=" * 54)
    res = validate_ip(test_input)
    if res.get('valid'):
        print(f"  Version:       {res.get('version')}")
        print(f"  IP Address:    {res.get('ip')}")
        if res.get('version') == 'IPv4':
            print(f"  Class:         Class {res.get('ipClass')} ({res.get('classRange')})")
            print(f"  Subnet Mask:   {res.get('defaultSubnet')} (CIDR: {res.get('cidrNotation')})")
            print(f"  Network Addr:  {res.get('networkAddress')}")
            print(f"  Broadcast:     {res.get('broadcastAddress')}")
            print(f"  Usable Hosts:  {res.get('firstUsableHost')} - {res.get('lastUsableHost')} ({res.get('maxHosts'):,} hosts)")
            print(f"  Special Type:  {res.get('specialType')}")
            print(f"  32-bit Binary: {res.get('binaryRepresentation')}")
        else:
            print(f"  Type:          {res.get('addressType')}")
            print(f"  Scope:         {res.get('scope')}")
            print(f"  Expanded:      {res.get('expanded')}")
            print(f"  128-bit Bin:   {res.get('binaryRepresentation')}")
    else:
        print(f"  Error:         {res.get('error')}")
    print("=" * 54 + "\n")

