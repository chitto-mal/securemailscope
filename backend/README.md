# SecureMailScope Offline Backend

Local demo backend for the SecureMailScope forensic pipeline.

## Run
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

Upload a PCAP/PCAPNG to demonstrate:
PCAP upload → packet parsing → mail-protocol recognition → TCP payload reconstruction → STARTTLS observation → TLS visibility → deterministic findings → posture score → local dashboard.

The prototype reports only evidence observable in the supplied capture and explicitly lists visibility limitations.

## Current forensic pipeline

The offline prototype now includes:

- PCAP/PCAPNG packet extraction
- Bidirectional mail-flow reconstruction
- SMTP/IMAP/POP3 identification
- STARTTLS observation
- TLS record parsing
- ClientHello/ServerHello metadata extraction
- Observable X.509 certificate inspection
- Deterministic evidence rules
- Bounded local Isolation Forest anomaly signal when enough sessions exist
- Explainable risk fusion
- JSON and PDF report endpoints
- Docker/Compose deployment for local offline use

### Report endpoints

- `POST /api/report/json` — upload a PCAP/PCAPNG and download a JSON report
- `POST /api/report/pdf` — upload a PCAP/PCAPNG and download a PDF report

The ML signal is optional and explicitly reports insufficient data when a capture does not contain enough comparable sessions. It does not replace deterministic forensic rules.


## Smoke test

From the repository root, after installing dependencies:

```bash
python -m unittest backend.test_smoke
```

The test builds a deterministic five-packet SMTP/STARTTLS/TLS capture in memory and verifies bidirectional session reconstruction, STARTTLS detection, TLS visibility, and handshake decoding.

## Demo fixture

Decode the committed base64 fixture into a local PCAP with:

```bash
python backend/demo/decode_fixture.py
```
