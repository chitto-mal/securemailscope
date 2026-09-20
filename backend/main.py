from __future__ import annotations
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
app = FastAPI(title="SecureMailScope Offline Analyzer", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def u16(b, o, e):
    return struct.unpack_from(e + "H", b, o)[0]


def u32(b, o, e):
    return struct.unpack_from(e + "I", b, o)[0]


def parse_pcap(data: bytes):
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return parse_pcapng(data)
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic not in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ):
        return []
    e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    link = u32(data, 20, e)
    off = 24
    out = []
    while off + 16 <= len(data):
        sec, usec, n, _ = struct.unpack_from(e + "IIII", data, off)
        if n > len(data) - off - 16:
            break
        out.append((sec + usec / 1e6, data[off + 16 : off + 16 + n], link))
        off += 16 + n
    return out


def parse_pcapng(data: bytes):
    if len(data) < 12 or data[:4] != b"\x0a\x0d\x0d\x0a":
        return []
    off = 0
    e = "<"
    interfaces = {}
    out = []
    while off + 12 <= len(data):
        typ = struct.unpack_from(e + "I", data, off)[0]
        if typ == 0x0A0D0D0A:
            bom = data[off + 8 : off + 12]
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        n = struct.unpack_from(e + "I", data, off + 4)[0]
        if n < 12 or off + n > len(data):
            break
        if typ == 1 and n >= 20:
            interfaces[len(interfaces)] = u16(data, off + 8, e)
        if typ == 6 and n >= 32:
            iface = u32(data, off + 8, e)
            hi = u32(data, off + 12, e)
            lo = u32(data, off + 16, e)
            cap = u32(data, off + 20, e)
            out.append(
                (
                    ((hi << 32) | lo) / 1e6,
                    data[off + 28 : off + 28 + cap],
                    interfaces.get(iface, 1),
                )
            )
        off += n
    return out


def tcp_payload(raw, link):
    off = (
        14
        if link == 1 and len(raw) >= 34
        else 16
        if link == 113 and len(raw) >= 36
        else 0
    )
    if len(raw) < off + 20 or raw[off] >> 4 != 4 or raw[off + 9] != 6:
        return None
    ihl = (raw[off] & 15) * 4
    if len(raw) < off + ihl + 20:
        return None
    src = ".".join(map(str, raw[off + 12 : off + 16]))
    dst = ".".join(map(str, raw[off + 16 : off + 20]))
    t = off + ihl
    sport, dport, seq = struct.unpack_from("!HHI", raw, t)
    th = ((raw[t + 12] >> 4) & 15) * 4
    return src, dst, sport, dport, seq, raw[t + th :]


def proto(port):
    return {
        25: "SMTP",
        587: "SMTP",
        465: "SMTPS",
        110: "POP3",
        995: "POP3S",
        143: "IMAP",
        993: "IMAPS",
    }.get(port)


def canonical_flow_key(src, sp, dst, dp):
    left = (src, sp)
    right = (dst, dp)
    return (left, right) if left <= right else (right, left)


def analyze(data: bytes, name: str):
    packets = parse_pcap(data)
    flows = {}

    for ts, raw, link in packets:
        p = tcp_payload(raw, link)
        if not p:
            continue

        src, dst, sp, dp, seq, payload = p
        pr = proto(sp) or proto(dp)
        sample = payload[:300].upper()

        if not pr and any(
            x in sample for x in (b"EHLO", b"HELO", b"STARTTLS", b"CAPABILITY")
        ):
            pr = "MAIL"
        if not pr:
            continue

        key = canonical_flow_key(src, sp, dst, dp)
        flow = flows.setdefault(
            key,
            {
                "src": src,
                "sp": sp,
                "dst": dst,
                "dp": dp,
                "protocol": pr,
                "parts": [],
                "directions": set(),
            },
        )

        # Keep the first observed endpoint as the display source/destination,
        # while storing every payload in the same bidirectional flow.
        flow["parts"].append((ts, src, sp, dst, dp, seq, payload))
        flow["directions"].add((src, sp, dst, dp))

    sessions = []
    findings = []
    counts = Counter()
    tls_versions = Counter()

    for flow in flows.values():
        # Sort by capture time so client requests and server responses are
        # reconstructed into one chronological conversation.
        ordered = sorted(flow["parts"], key=lambda item: item[0])

        # Basic duplicate suppression for retransmitted TCP payloads.
        seen = set()
        unique = []
        for item in ordered:
            _, src, sp, dst, dp, seq, payload = item
            marker = (src, sp, dst, dp, seq, payload)
            if marker in seen:
                continue
            seen.add(marker)
            unique.append(item)

        stream = b"".join(item[6] for item in unique)
        text = stream.decode("latin1", "ignore").upper()
        has_starttls = "STARTTLS" in text

        tls_records = [
            item[6]
            for item in unique
            if len(item[6]) >= 5 and item[6][0] == 0x16
        ]
        tls_seen = bool(tls_records)
        version = None

        if tls_records:
            version = f"{tls_records[0][1]}.{tls_records[0][2]}"
            tls_versions[version] += 1

        counts[flow["protocol"]] += 1
        sf = []

        if has_starttls:
            sf.append(
                {
                    "severity": "info",
                    "title": "STARTTLS transition observed",
                    "evidence": "STARTTLS was visible in the reconstructed bidirectional mail stream.",
                }
            )

        if has_starttls and not tls_seen:
            sf.append(
                {
                    "severity": "medium",
                    "title": "TLS handshake not observed after STARTTLS",
                    "evidence": "STARTTLS was visible, but no TLS handshake record was observable in this flow.",
                }
            )

        if version in ("3.1", "3.2"):
            sf.append(
                {
                    "severity": "high",
                    "title": "Legacy TLS record version observed",
                    "evidence": f"TLS record legacy version {version} was visible.",
                }
            )

        sid = f"S{len(sessions) + 1:03d}"
        for finding in sf:
            findings.append({**finding, "session": sid})

        first = unique[0] if unique else flow["parts"][0]
        last = unique[-1] if unique else flow["parts"][-1]

        sessions.append(
            {
                "id": sid,
                "protocol": flow["protocol"],
                "source": f"{first[1]}:{first[2]}",
                "destination": f"{first[3]}:{first[4]}",
                "packets": len(unique),
                "bytes": sum(len(item[6]) for item in unique),
                "starttls": has_starttls,
                "tls_seen": tls_seen,
                "tls_version": version,
                "findings": sf,
                "bidirectional": len(flow["directions"]) > 1,
                "start_time": first[0],
                "end_time": last[0],
            }
        )

    score = max(
        0,
        100
        - sum(
            {"high": 20, "medium": 10, "low": 5, "critical": 30}.get(
                x["severity"], 0
            )
            for x in findings
        ),
    )
    level = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 80 else "LOW"

    return {
        "filename": name,
        "offline": True,
        "packet_count": len(packets),
        "tcp_mail_sessions": len(sessions),
        "protocol_counts": dict(counts),
        "tls_versions": dict(tls_versions),
        "score": score,
        "risk_level": level,
        "findings": findings,
        "sessions": sessions,
        "limitations": [
            "Only information present in the capture can be assessed.",
            "Missing or truncated traffic can reduce visibility.",
            "TCP reassembly is currently capture-order based and is not yet a full retransmission/reordering engine.",
            "Certificate details are reported only when observable in captured TLS data.",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "offline", "version": app.version}


@app.post("/api/analyze")
async def api_analyze(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        return JSONResponse(
            status_code=413, content={"error": "Capture exceeds 50 MB demo limit."}
        )
    try:
        return analyze(data, file.filename or "capture.pcap")
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


app.mount("/assets", StaticFiles(directory=WEB), name="assets")
