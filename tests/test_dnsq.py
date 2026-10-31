import struct

from dorm_ip import dnsq


def answer(qid, ips, domain="portal.dorm.local", rcode=0):
    q = dnsq.build_dns_query(domain, qid)
    header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(ips), 0, 0)
    body = q[12:]
    for ip in ips:  # name as a compression pointer to offset 12
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split("."))
    return header + body


def test_parse_a_records():
    assert dnsq.parse_a_records(answer(7, ["172.18.32.50", "172.18.32.51"]), 7) == ["172.18.32.50", "172.18.32.51"]
    assert dnsq.parse_a_records(answer(7, []), 7) == []
    assert dnsq.parse_a_records(answer(7, ["1.2.3.4"]), 8) == []  # wrong id
    assert dnsq.parse_a_records(answer(7, ["1.2.3.4"], rcode=3), 7) == []  # NXDOMAIN
    assert dnsq.parse_a_records(answer(7, ["1.2.3.4"])[:-3], 7) == []  # truncated: no crash
    assert dnsq.parse_a_records(b"", 1) == []


def test_resolve_via_skips_ipv6_and_failures(monkeypatch):
    answers = {"10.0.0.1": ([], None), "10.0.0.2": (["9.9.9.9"], 3.0)}
    monkeypatch.setattr(dnsq, "query_a", lambda s, d, timeout=2.0: answers[s])
    assert dnsq.resolve_via(["::1", "10.0.0.1", "10.0.0.2"], "x.y") == "9.9.9.9"
    assert dnsq.resolve_via(["10.0.0.1"], "x.y") is None