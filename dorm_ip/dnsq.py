"""Minimal DNS over UDP: build A queries and parse A answers (stdlib only).

Used to time the active DNS server and to resolve the portal host through the dorm
DNS directly, without touching the system DNS settings.
"""

from __future__ import annotations

import random
import socket
import struct
import time


def build_dns_query(domain: str, qid: int) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.strip(".").split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def dns_response_ok(data: bytes, qid: int) -> bool:
    if len(data) < 12:
        return False
    rid, flags, _qd, an = struct.unpack("!HHHH", data[:8])
    return rid == qid and bool(flags & 0x8000) and (flags & 0xF) == 0 and an > 0


def _skip_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return off + 2
        off += 1 + length


def parse_a_records(data: bytes, qid: int) -> list[str]:
    """IPv4 addresses from the answer section (empty if the response is not a good answer)."""
    if not dns_response_ok(data, qid):
        return []
    qd, an = struct.unpack("!HH", data[4:8])
    ips: list[str] = []
    try:
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off) + 4
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off : off + 10])
            off += 10
            if off + rdlen > len(data):
                break  # truncated record
            if rtype == 1 and rclass == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in data[off : off + 4]))
            off += rdlen
    except (ValueError, struct.error):
        pass
    return ips


def query_a(server: str, domain: str, timeout: float = 2.0) -> tuple[list[str], float | None]:
    """Ask `server` directly (UDP/53). -> (A records, milliseconds); ([], None) on failure."""
    qid = random.randrange(0x10000)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            s.sendto(build_dns_query(domain, qid), (server, 53))
            while True:
                data, _ = s.recvfrom(2048)
                ips = parse_a_records(data, qid)
                if ips:
                    return ips, (time.perf_counter() - t0) * 1000
                if time.perf_counter() - t0 > timeout:
                    return [], None
        except OSError:
            return [], None


def resolve_via(servers: list[str], host: str, timeout: float = 2.0) -> str | None:
    """First A record for `host` from the first of `servers` that answers."""
    for server in servers:
        if ":" in server:
            continue
        ips, _ms = query_a(server, host, timeout)
        if ips:
            return ips[0]
    return None