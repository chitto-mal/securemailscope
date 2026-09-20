import struct
import unittest

from backend.main import analyze


def packet(src, dst, sport, dport, seq, payload):
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    src_ip = bytes(map(int, src.split(".")))
    dst_ip = bytes(map(int, dst.split(".")))
    total = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, src_ip, dst_ip)
    tcp = struct.pack("!HHII", sport, dport, seq, 0) + bytes([0x50, 0x18]) + struct.pack("!HHH", 65535, 0, 0)
    return eth + ip + tcp + payload


def demo_pcap():
    packets = [
        packet("10.0.0.10", "10.0.0.20", 52344, 25, 1, b"EHLO mail.example\r\n"),
        packet("10.0.0.20", "10.0.0.10", 25, 52344, 1, b"250-STARTTLS\r\n250 OK\r\n"),
        packet("10.0.0.10", "10.0.0.20", 52344, 25, 20, b"STARTTLS\r\n"),
        packet("10.0.0.20", "10.0.0.10", 25, 52344, 40, b"220 Ready to start TLS\r\n"),
    ]
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + b"\x00\x00"
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    tls = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
    packets.append(packet("10.0.0.10", "10.0.0.20", 52344, 25, 52, tls))

    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, item in enumerate(packets):
        data += struct.pack("<IIII", 1700000000 + i, 0, len(item), len(item)) + item
    return data


class SecureMailScopeSmokeTest(unittest.TestCase):
    def test_starttls_tls_session(self):
        result = analyze(demo_pcap(), "smoke.pcap")
        self.assertEqual(result["packet_count"], 5)
        self.assertEqual(result["tcp_mail_sessions"], 1)
        session = result["sessions"][0]
        self.assertTrue(session["bidirectional"])
        self.assertTrue(session["starttls"])
        self.assertTrue(session["tls_seen"])
        self.assertGreaterEqual(session["tls_handshake_count"], 1)
        self.assertEqual(result["protocol_counts"]["SMTP"], 1)


if __name__ == "__main__":
    unittest.main()
