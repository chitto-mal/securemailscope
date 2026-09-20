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
app = FastAPI(title="SecureMailScope Offline Analyzer", version="0.2.0")
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
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return []
    e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    link = u32(data, 20, e)
    off = 24
    out = []
    while off + 16 <= len(data):
        sec, usec, n, _ = struct.unpack_from(e + "IIII", data, off)
        if n > len(data) - off - 16:
            break
        out.append((sec + usec / 1e6, data[off + 16:off + 16 + n], link))
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
            bom = data[off + 8:off + 12]
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
            out.append((((hi << 32) | lo) / 1e6, data[off + 28:off + 28 + cap], interfaces.get(iface, 1)))
        off += n
    return out


def tcp_payload(raw, link):
    off = 14 if link == 1 and len(raw) >= 34 else 16 if link == 113 and len(raw) >= 36 else 0
    if len(raw) < off + 20 or raw[off] >> 4 != 4 or raw[off + 9] != 6:
        return None
    ihl = (raw[off] & 15) * 4
    if len(raw) < off + ihl + 20:
        return None
    src = ".".join(map(str, raw[off + 12:off + 16]))
    dst = ".".join(map(str, raw[off + 16:off + 20]))
    t = off + ihl
    sport, dport, seq = struct.unpack_from("!HHI", raw, t)
    th = ((raw[t + 12] >> 4) & 15) * 4
    return src, dst, sport, dport, seq, raw[t + th:]


def proto(port):
    return {25: "SMTP", 587: "SMTP", 465: "SMTPS", 110: "POP3", 995: "POP3S", 143: "IMAP", 993: "IMAPS"}.get(port)


def canonical_flow_key(src, sp, dst, dp):
    left, right = (src, sp), (dst, dp)
    return (left, right) if left <= right else (right, left)


def parse_tls_records(stream: bytes):
    records = []
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        legacy_major = stream[offset + 1]
        legacy_minor = stream[offset + 2]
        length = struct.unpack_from("!H", stream, offset + 3)[0]
        end = offset + 5 + length
        if end > len(stream):
            return records, {"status": "incomplete", "offset": offset, "expected": length, "available": max(0, len(stream) - offset - 5)}
        payload = stream[offset + 5:end]
        records.append({
            "content_type": content_type,
            "content_type_name": {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}.get(content_type, "unknown"),
            "legacy_version": f"{legacy_major}.{legacy_minor}",
            "length": length,
            "payload": payload,
        })
        offset = end
    return records, {"status": "complete" if offset == len(stream) else "trailing_bytes", "offset": offset}


def parse_handshakes(record_payload: bytes):
    messages = []
    offset = 0
    while offset + 4 <= len(record_payload):
        msg_type = record_payload[offset]
        length = int.from_bytes(record_payload[offset + 1:offset + 4], "big")
        end = offset + 4 + length
        if end > len(record_payload):
            return messages, False
        body = record_payload[offset + 4:end]
        messages.append((msg_type, body))
        offset = end
    return messages, offset == len(record_payload)


def parse_client_hello(body: bytes):
    result = {"supported_versions": [], "cipher_suites": [], "server_name": None, "extensions": []}
    if len(body) < 34:
        return result
    legacy_version = f"{body[0]}.{body[1]}"
    result["legacy_version"] = legacy_version
    pos = 34
    if pos >= len(body):
        return result
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return result
    cipher_len = struct.unpack_from("!H", body, pos)[0]
    pos += 2
    if pos + cipher_len > len(body):
        return result
    result["cipher_suites"] = [f"0x{body[i]:02x}{body[i+1]:02x}" for i in range(pos, pos + cipher_len, 2) if i + 1 < pos + cipher_len]
    pos += cipher_len
    if pos >= len(body):
        return result
    comp_len = body[pos]
    pos += 1 + comp_len
    if pos + 2 > len(body):
        return result
    ext_len = struct.unpack_from("!H", body, pos)[0]
    pos += 2
    ext_end = min(len(body), pos + ext_len)
    while pos + 4 <= ext_end:
        ext_type = struct.unpack_from("!H", body, pos)[0]
        ext_size = struct.unpack_from("!H", body, pos + 2)[0]
        pos += 4
        if pos + ext_size > ext_end:
            break
        ext_body = body[pos:pos + ext_size]
        result["extensions"].append(f"0x{ext_type:04x}")
        if ext_type == 0 and len(ext_body) >= 5:
            list_len = struct.unpack_from("!H", ext_body, 0)[0]
            if list_len >= 3 and len(ext_body) >= 5:
                name_len = struct.unpack_from("!H", ext_body, 3)[0]
                if 5 + name_len <= len(ext_body):
                    result["server_name"] = ext_body[5:5 + name_len].decode("idna", "ignore")
        elif ext_type == 43 and len(ext_body) >= 3:
            versions_len = ext_body[0]
            for i in range(1, min(len(ext_body), 1 + versions_len), 2):
                if i + 1 < len(ext_body):
                    result["supported_versions"].append(f"{ext_body[i]}.{ext_body[i+1]}")
        pos += ext_size
    return result


def parse_server_hello(body: bytes):
    result = {"cipher_suite": None, "extensions": [], "selected_version": None}
    if len(body) < 38:
        return result
    result["legacy_version"] = f"{body[0]}.{body[1]}"
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 3 > len(body):
        return result
    suite = struct.unpack_from("!H", body, pos)[0]
    result["cipher_suite"] = f"0x{suite:04x}"
    pos += 3
    if pos + 2 > len(body):
        return result
    ext_len = struct.unpack_from("!H", body, pos)[0]
    pos += 2
    ext_end = min(len(body), pos + ext_len)
    while pos + 4 <= ext_end:
        ext_type = struct.unpack_from("!H", body, pos)[0]
        ext_size = struct.unpack_from("!H", body, pos + 2)[0]
        pos += 4
        if pos + ext_size > ext_end:
            break
        ext_body = body[pos:pos + ext_size]
        result["extensions"].append(f"0x{ext_type:04x}")
        if ext_type == 43 and len(ext_body) >= 2:
            result["selected_version"] = f"{ext_body[0]}.{ext_body[1]}"
        pos += ext_size
    return result


def parse_certificate_message(body: bytes):
    certs = []
    if len(body) < 3:
        return certs, False
    total_len = int.from_bytes(body[0:3], "big")
    end = min(len(body), 3 + total_len)
    pos = 3
    complete = end == 3 + total_len
    while pos + 3 <= end:
        cert_len = int.from_bytes(body[pos:pos + 3], "big")
        pos += 3
        if pos + cert_len > end:
            return certs, False
        certs.append(body[pos:pos + cert_len])
        pos += cert_len
        if pos < end:
            if pos + 2 > end:
                return certs, False
            ext_len = int.from_bytes(body[pos:pos + 2], "big")
            pos += 2 + ext_len
            if pos > end:
                return certs, False
    return certs, complete and pos == end


def inspect_x509_certificate(der: bytes):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

    cert = x509.load_der_x509_certificate(der)

    def name_value(name):
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type, key_size = "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type, key_size = "EC", public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_type, key_size = "Ed25519", 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        key_type, key_size = "Ed448", 448
    else:
        key_type, key_size = type(public_key).__name__, None

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return {
        "subject": name_value(cert.subject),
        "issuer": name_value(cert.issuer),
        "serial_number": str(cert.serial_number),
        "version": cert.version.name,
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "public_key_type": key_type,
        "public_key_size": key_size,
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "self_signed": cert.subject == cert.issuer,
        "san": [
            value.value
            for ext in cert.extensions
            if ext.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            for value in ext.value
        ],
    }


def extract_certificates(tls_handshakes):
    certificates = []
    errors = []
    for item in tls_handshakes:
        if item["name"] != "Certificate":
            continue
        body = item.get("_body")
        if body is None:
            continue
        raw_certs, complete = parse_certificate_message(body)
        if not complete:
            errors.append("A Certificate handshake message was incomplete or truncated.")
        for der in raw_certs:
            try:
                certificates.append(inspect_x509_certificate(der))
            except Exception:
                errors.append("Certificate could not be decoded.")
    return certificates, errors


def tls_handshake_summary(records):
    handshakes = []
    for record in records:
        if record["content_type"] != 22:
            continue
        messages, complete = parse_handshakes(record["payload"])
        for msg_type, body in messages:
            name = {
                1: "ClientHello",
                2: "ServerHello",
                11: "Certificate",
                14: "ServerHelloDone",
                20: "Finished",
            }.get(msg_type, f"Handshake({msg_type})")
            item = {"type": msg_type, "name": name, "length": len(body), "_body": body}
            if msg_type == 1:
                item["details"] = parse_client_hello(body)
            elif msg_type == 2:
                item["details"] = parse_server_hello(body)
            elif msg_type == 11:
                raw_certs, complete = parse_certificate_message(body)
                item["certificate_count"] = len(raw_certs)
                item["certificate_parse_complete"] = complete
            handshakes.append(item)
        if not complete:
            return handshakes, False
    return handshakes, True


def analyze_tls_direction(payloads):
    stream = b"".join(payloads)
    records, record_status = parse_tls_records(stream)
    handshakes, handshake_complete = tls_handshake_summary(records)
    return records, handshakes, record_status, handshake_complete


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
        if not pr and any(x in sample for x in (b"EHLO", b"HELO", b"STARTTLS", b"CAPABILITY")):
            pr = "MAIL"
        if not pr:
            continue
        key = canonical_flow_key(src, sp, dst, dp)
        flow = flows.setdefault(key, {"protocol": pr, "parts": [], "directions": set()})
        flow["parts"].append((ts, src, sp, dst, dp, seq, payload))
        flow["directions"].add((src, sp, dst, dp))

    sessions, findings, counts, tls_versions = [], [], Counter(), Counter()
    for flow in flows.values():
        ordered = sorted(flow["parts"], key=lambda item: item[0])
        seen, unique = set(), []
        for item in ordered:
            _, src, sp, dst, dp, seq, payload = item
            marker = (src, sp, dst, dp, seq, payload)
            if marker not in seen:
                seen.add(marker)
                unique.append(item)

        pre_tls, post_tls = [], []
        tls_started = False
        for item in unique:
            payload = item[6]
            if not tls_started and (len(payload) >= 5 and payload[0] == 0x16 and payload[1] in (3,) and payload[2] in (0,1,2,3,4)):
                tls_started = True
            if tls_started:
                post_tls.append(item)
            else:
                pre_tls.append(item)

        cleartext = b"".join(item[6] for item in pre_tls)
        text = cleartext.decode("latin1", "ignore").upper()
        has_starttls = "STARTTLS" in text
        directions = {}
        for item in post_tls:
            key = (item[1], item[2], item[3], item[4])
            directions.setdefault(key, []).append(item[6])

        tls_records = []
        tls_handshakes = []
        tls_complete = True
        tls_record_status = {"status": "not_observed"}
        tls_direction_details = []
        for direction, payloads in directions.items():
            records, handshakes, record_status, handshake_complete = analyze_tls_direction(payloads)
            tls_records.extend(records)
            tls_handshakes.extend(handshakes)
            tls_record_status = record_status if record_status.get("status") != "not_observed" else tls_record_status
            tls_complete = tls_complete and handshake_complete
            tls_direction_details.append({
                "direction": f"{direction[0]}:{direction[1]} -> {direction[2]}:{direction[3]}",
                "record_count": len(records),
                "handshake_count": len(handshakes),
                "handshakes": handshakes,
            })

        tls_seen = bool(tls_records)
        version = tls_records[0]["legacy_version"] if tls_records else None
        if version:
            tls_versions[version] += 1
        counts[flow["protocol"]] += 1

        sf = []
        if has_starttls:
            sf.append({"severity": "info", "title": "STARTTLS transition observed", "evidence": "STARTTLS was visible in the reconstructed bidirectional mail stream."})
        if has_starttls and not tls_seen:
            sf.append({"severity": "medium", "title": "TLS handshake not observed after STARTTLS", "evidence": "STARTTLS was visible, but no TLS handshake record was observable in this flow."})
        if version in ("3.1", "3.2"):
            sf.append({"severity": "high", "title": "Legacy TLS record version observed", "evidence": f"TLS record legacy version {version} was visible."})
        if tls_seen and not tls_handshakes:
            sf.append({"severity": "medium", "title": "TLS records observed but handshake messages were not decoded", "evidence": "TLS record framing was visible, but no complete handshake message was decoded from the captured direction."})

        sid = f"S{len(sessions)+1:03d}"
        for finding in sf:
            findings.append({**finding, "session": sid})

        first, last = unique[0], unique[-1]
        client_hello = next((x for x in tls_handshakes if x["name"] == "ClientHello"), None)
        server_hello = next((x for x in tls_handshakes if x["name"] == "ServerHello"), None)
        certificates, certificate_errors = extract_certificates(tls_handshakes)
        for item in tls_handshakes:
            item.pop("_body", None)
        sessions.append({
            "id": sid,
            "protocol": flow["protocol"],
            "source": f"{first[1]}:{first[2]}",
            "destination": f"{first[3]}:{first[4]}",
            "packets": len(unique),
            "bytes": sum(len(x[6]) for x in unique),
            "starttls": has_starttls,
            "tls_seen": tls_seen,
            "tls_version": version,
            "bidirectional": len(flow["directions"]) > 1,
            "tls_record_count": len(tls_records),
            "tls_handshake_count": len(tls_handshakes),
            "tls_handshake_complete": tls_complete and bool(tls_handshakes),
            "client_hello": client_hello,
            "server_hello": server_hello,
            "certificates": certificates,
            "certificate_errors": certificate_errors,
            "tls_directions": tls_direction_details,
            "findings": sf,
            "start_time": first[0],
            "end_time": last[0],
        })

    score = max(0, 100 - sum({"high":20, "medium":10, "low":5, "critical":30}.get(x["severity"], 0) for x in findings))
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
            "TLS handshake parsing currently covers common ClientHello and ServerHello fields; fragmented handshake messages across TCP/TLS records require further reassembly work.",
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
        return JSONResponse(status_code=413, content={"error": "Capture exceeds 50 MB demo limit."})
    try:
        return analyze(data, file.filename or "capture.pcap")
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


app.mount("/assets", StaticFiles(directory=WEB), name="assets")
