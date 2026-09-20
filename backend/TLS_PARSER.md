# TLS Handshake Parser

SecureMailScope now extracts observable TLS record and handshake metadata from reconstructed mail flows.

## Current extraction

- TLS record content type
- TLS record legacy version
- TLS record length
- ClientHello
- ServerHello
- ClientHello supported_versions extension
- ClientHello cipher-suite list
- ClientHello SNI when visible
- ClientHello extension identifiers
- ServerHello selected version when the supported_versions extension is visible
- ServerHello selected cipher suite
- Handshake completeness status
- X.509 certificate chain entries when a Certificate handshake is visible
- Certificate subject and issuer common names
- Certificate validity window and expired/not-yet-valid status
- Public-key type and size
- Signature hash algorithm
- Self-signed status
- Subject Alternative Names (SANs)

## Evidence rule

The parser reports only what is visible in the capture. It does not infer a TLS property that is missing because the capture is truncated, encrypted beyond the observable handshake, or incomplete.

## Current limitation

Handshake messages that are fragmented across TCP segments or split across TLS records require a deeper byte-stream reassembly layer. The current prototype is intentionally conservative and reports incomplete visibility instead of guessing.

## Next layers

1. X.509 certificate parsing
2. Standards-based deterministic rules
3. Risk fusion
4. ML anomaly signal
