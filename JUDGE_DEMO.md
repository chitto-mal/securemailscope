# SecureMailScope — Judge Demo

This is a deterministic offline demonstration fixture for the SIH presentation.

## What it demonstrates

The fixture contains four reconstructed mail sessions:

1. SMTP STARTTLS followed by a visible TLS ClientHello.
2. SMTP STARTTLS followed by a legacy TLS 1.0 record, exercising the legacy-version rule.
3. SMTP STARTTLS with no visible TLS record afterward, exercising the STARTTLS-transition finding.
4. IMAP STARTTLS followed by a visible TLS ClientHello.

The fixture is synthetic and is **not real incident evidence**. It exists so the same demo produces repeatable results on a judge laptop without Internet access or a live mail server.

## Run the demo

### Windows PowerShell

From the repository root:

    python backend/demo/decode_judge_demo.py
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

Then open:

    http://127.0.0.1:8000

Choose `backend/demo/judge_demo.pcap` and select **Analyze PCAP**.

### Docker

From the repository root:

    docker compose up --build

Then open `http://127.0.0.1:8000` and upload the decoded fixture.

## Judge presentation sequence

1. Start the application before the presentation.
2. Disconnect Wi-Fi if you want to demonstrate that the forensic analysis itself is offline.
3. Upload `judge_demo.pcap`.
4. Point out the packet/session counts and protocol visibility.
5. Show the reconstructed SMTP and IMAP sessions.
6. Show STARTTLS transition evidence and the TLS ClientHello evidence.
7. Show the legacy TLS finding and the missing-visible-TLS-after-STARTTLS finding.
8. Open the JSON or PDF report to demonstrate exportability.
9. Explain that every finding is tied to observed PCAP evidence and that missing capture data limits what can be concluded.

## Important evidence note

Do not describe the synthetic fixture as a captured attack or production incident. Its purpose is reproducibility: it lets judges see the complete analysis pipeline consistently.
