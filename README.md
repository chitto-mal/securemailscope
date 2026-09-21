# SecureMailScope 🛡️
> **AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**  
> *Developed for National Technical Research Organisation (NTRO) | Smart India Hackathon (SIH 2026)*

---

## 📌 Overview

**SecureMailScope** is a passive, offline-first network forensic application that ingests `.pcap` / `.pcapng` capture files containing SMTP, IMAP, and POP3 mail traffic. It correlates observable protocol, STARTTLS, TLS and X.509 evidence into an explainable **Cryptographic Security Posture Score (0–100)** and prioritized findings.

The prototype combines deterministic forensic rules with an optional local Isolation Forest anomaly signal. It does not require live mail-server access or a cloud service for analysis.

## ✨ Current Prototype Capabilities

- **Offline PCAP/PCAPNG ingestion**
- **Bidirectional TCP mail-flow reconstruction**
- **SMTP / IMAP / POP3 identification**
- **STARTTLS transition observation**
- **TLS record parsing**
- **ClientHello / ServerHello metadata extraction**
- **Observable X.509 certificate inspection**
- **Deterministic security findings and remediation guidance**
- **Bounded local ML anomaly signal**
- **Explainable risk fusion**
- **JSON and PDF forensic reports**
- **Local web dashboard**
- **Docker / Docker Compose support**

### Evidence boundary

SecureMailScope reports only what is observable in the supplied capture. Missing, truncated, encrypted or otherwise unavailable evidence is not treated as proof of a security property. Certificate findings are produced only when certificate data is visible and decodable.

---

## 🏗️ Backend Architecture

The backend now follows a lightweight layered architecture:

```text
HTTP Request
     │
     ▼
┌──────────────────────┐
│ Controller Layer     │
│ analysis_controller  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Service Layer        │
│ analysis_service     │
└──────────┬───────────┘
           │
           ├──────────────► Capture Repository
           │
           ▼
┌──────────────────────┐
│ Forensic Analyzer    │
│ backend/main.py      │
│ PCAP → TLS → X.509   │
└──────────┬───────────┘
           │
           ├──────────────► Rules Engine
           ├──────────────► ML Anomaly Signal
           └──────────────► Risk Fusion
           │
           ▼
┌──────────────────────┐
│ Report Repository    │
│ JSON / PDF generation│
└──────────┬───────────┘
           ▼
      API Response
```

### Layer responsibilities

| Layer | Location | Responsibility |
|---|---|---|
| **Controller** | `backend/controllers/` | Handles HTTP requests, uploads, errors and API responses |
| **Service** | `backend/services/` | Coordinates application workflow and repository access |
| **Repository** | `backend/repositories/` | Abstracts capture input and report output boundaries |
| **Forensic engine** | `backend/main.py` | PCAP parsing, TCP flows, mail protocol, STARTTLS, TLS and X.509 analysis |
| **Rules** | `backend/rules.py` | Deterministic security findings |
| **ML** | `backend/ml_anomaly.py` | Optional local Isolation Forest anomaly signal |
| **Risk fusion** | `backend/risk_fusion.py` | Combines deterministic and bounded ML penalties |
| **Reporting** | `backend/reporting.py` | Builds JSON and PDF report content |
| **Web UI** | `backend/web/` | Local offline dashboard |

### Backend structure

```text
backend/
├── __init__.py
├── main.py
├── requirements.txt
├── README.md
├── TLS_PARSER.md
├── rules.py
├── risk_fusion.py
├── ml_anomaly.py
├── reporting.py
│
├── controllers/
│   ├── __init__.py
│   └── analysis_controller.py
│
├── services/
│   ├── __init__.py
│   └── analysis_service.py
│
├── repositories/
│   ├── __init__.py
│   ├── capture_repository.py
│   └── report_repository.py
│
└── web/
    └── index.html
```

### Why use these layers?

The controller/service/repository separation keeps the HTTP API from becoming tightly coupled to storage and workflow concerns.

It also leaves clear extension points for future SIH development:

- replace the in-memory capture repository with persistent evidence storage if required;
- add PostgreSQL repositories without changing controller contracts;
- add SIEM/export repositories;
- move the forensic analyzer into a dedicated domain module as the codebase grows;
- unit-test services and repositories independently from FastAPI.

**Current repository implementation is intentionally lightweight and offline. A database is not required for the current demo.**

---

## 🔬 Forensic Processing Flow

```text
PCAP / PCAPNG
      ↓
Packet Extraction
      ↓
TCP Flow Reconstruction
      ↓
SMTP / IMAP / POP3 Identification
      ↓
STARTTLS State Observation
      ↓
TLS Record + Handshake Parsing
      ↓
X.509 Certificate Analysis
      ↓
Deterministic Rule Engine
      ├──────────────┐
      ▼              ▼
Explainable Rules   ML Anomaly Signal
      └──────┬───────┘
             ▼
        Risk Fusion
             ↓
   Cryptographic Security
      Posture Score
             ↓
      Dashboard / Reports
             ↓
       PDF / JSON
```

---

## 🚀 Quick Start

### Option 1 — Docker Compose

From the repository root:

```bash
docker compose up --build
```

Then open:

```text
http://127.0.0.1:8000
```

This runs the backend locally and does not require a cloud service.

### Option 2 — Python

Requirements:

- Python 3.11+
- pip

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r backend/requirements.txt

uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

---

## 🔌 API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Offline dashboard |
| `/api/health` | GET | Backend health check |
| `/api/analyze` | POST | Analyze a PCAP/PCAPNG and return JSON evidence |
| `/api/report/json` | POST | Generate downloadable JSON report |
| `/api/report/pdf` | POST | Generate downloadable PDF report |

Example health response:

```json
{
  "status": "ok",
  "mode": "offline",
  "version": "0.2.0"
}
```

---

## 🧪 Testing / Demo

The backend documentation contains the smoke-test and demo-fixture workflow:

```bash
python -m unittest backend.test_smoke
python backend/demo/decode_fixture.py
```

The test fixture is intended to exercise bidirectional SMTP/STARTTLS/TLS parsing without depending on a live mail server.

---

## 📚 Standards & References

The project currently maps its security-analysis direction to established TLS/email security guidance including:

- **IETF RFC 8996** — Deprecating TLS 1.0 and TLS 1.1
- **NIST SP 800-52r2** — Guidelines for TLS implementations
- **IETF RFC 7465** — Prohibiting RC4 Cipher Suites
- **IETF RFC 8461** — SMTP MTA Strict Transport Security (MTA-STS)

These references inform the prototype's detection direction; the current implementation should not be represented as a complete standards-compliance certification engine.

---

## ⚠️ Current Prototype Limitations

- TLS handshake messages fragmented across TCP segments/TLS records require further reassembly work.
- PCAPNG support is intentionally basic.
- TCP retransmission/reordering handling is limited.
- Certificate details require certificate bytes to be visible in the capture.
- ML anomaly detection needs enough comparable sessions; otherwise it reports `insufficient_data`.
- The repository layer currently uses in-memory processing rather than PostgreSQL.
- The deterministic rule set is a prototype and should be expanded and validated before production deployment.

---

## 📜 License

Distributed under the MIT License. Developed for NTRO Smart India Hackathon (SIH 2026).
