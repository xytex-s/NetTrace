import unittest
import socket
import struct
from unittest.mock import patch, MagicMock
from sniffer import (
    parse_ether_header,
    parse_ip_header,
    parse_tcp_header,
    parse_udp_header,
    parse_icmp_header,
    get_mac_str
)

def validate_ip(ip_str):
    try:
        parts = ip_str.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

class TestSniffer(unittest.TestCase):
    def test_get_mac_str(self):
        test_bytes = b'\x00\x0c\x29\xaf\xfa\x5e'
        expected = '00:0C:29:AF:FA:5E'
        self.assertEqual(get_mac_str(test_bytes), expected)

    def test_validate_ip(self):
        self.assertTrue(validate_ip('192.168.1.1'))
        self.assertTrue(validate_ip('10.0.0.1'))
        self.assertFalse(validate_ip('256.256.256.256'))
        self.assertFalse(validate_ip('not.an.ip.address'))

    def test_parse_ether_header(self):
        # Create a mock ethernet frame
        dest_mac = b'\x00\x0c\x29\xaf\xfa\x5e'
        src_mac = b'\x00\x0c\x29\xaf\xfa\x5f'
        payload = b'test_payload'
        frame = struct.pack('!6s6sH', dest_mac, src_mac, 0x0800) + payload

        dest, src, eth_proto, data = parse_ether_header(frame)
        self.assertEqual(dest, '00:0C:29:AF:FA:5E')
        self.assertEqual(src, '00:0C:29:AF:FA:5F')
        self.assertEqual(eth_proto, 8)  # IPv4
        self.assertEqual(data, b'test_payload')

    def test_parse_ip_header(self):
        # Create a mock IP header
        header = (
            b'\x45\x00\x00\x28'  # Version, IHL, DSCP, Total Length
            b'\x00\x00\x40\x00'  # ID, Flags, Fragment Offset
            b'\x40\x06\x00\x00'  # TTL, Protocol (TCP), Checksum
            b'\xc0\xa8\x01\x01'  # Source IP (192.168.1.1)
            b'\xc0\xa8\x01\x02'  # Dest IP (192.168.1.2)
            b'payload'
        )
        
        version, header_length, ttl, proto, src, dst, data = parse_ip_header(header)
        self.assertEqual(version, 4)
        self.assertEqual(header_length, 20)
        self.assertEqual(ttl, 64)
        self.assertEqual(proto, 6)  # TCP
        self.assertEqual(src, '192.168.1.1')
        self.assertEqual(dst, '192.168.1.2')
        self.assertEqual(data, b'payload')

    def test_parse_tcp_header(self):
        # Create a mock TCP header
        header = (
            b'\x00\x50\x23\x28'  # Source Port (80), Dest Port (9000)
            b'\x00\x00\x00\x01'  # Sequence Number
            b'\x00\x00\x00\x02'  # Acknowledgment Number
            b'\x50\x18\x00\x00'  # Data Offset, Flags
            b'payload'
        )

        src_port, dest_port, seq, ack, offset, data = parse_tcp_header(header)
        self.assertEqual(src_port, 80)
        self.assertEqual(dest_port, 9000)
        self.assertEqual(seq, 1)
        self.assertEqual(ack, 2)
        self.assertEqual(offset, 20)
        self.assertEqual(data, b'payload')

    def test_parse_udp_header(self):
        # Create a mock UDP header
        header = (
            b'\x00\x35\x23\x28'  # Source Port (53), Dest Port (9000)
            b'\x00\x08\x00\x00'  # Length, Checksum
            b'payload'
        )

        src_port, dest_port, size, data = parse_udp_header(header)
        self.assertEqual(src_port, 53)
        self.assertEqual(dest_port, 9000)
        self.assertEqual(size, 8)  # UDP header length
        self.assertEqual(data, b'payload')

    def test_parse_icmp_header(self):
        # Create a mock ICMP header
        header = (
            b'\x08\x00'  # Type (8 = Echo Request), Code (0)
            b'\x00\x00'  # Checksum
            b'payload'
        )

        icmp_type, code, checksum, data = parse_icmp_header(header)
        self.assertEqual(icmp_type, 8)
        self.assertEqual(code, 0)
        self.assertEqual(data, b'payload')

if __name__ == '__main__':
    unittest.main()