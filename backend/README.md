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