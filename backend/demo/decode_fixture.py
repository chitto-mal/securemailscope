from pathlib import Path
import base64

HERE = Path(__file__).resolve().parent
source = HERE / "synthetic_starttls.pcap.b64"
target = HERE / "synthetic_starttls.pcap"

target.write_bytes(base64.b64decode(source.read_text().strip()))
print(f"Wrote {target}")
