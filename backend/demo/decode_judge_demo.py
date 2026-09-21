from pathlib import Path
import base64

HERE = Path(__file__).resolve().parent
source = HERE / "judge_demo.pcap.b64"
target = HERE / "judge_demo.pcap"
target.write_bytes(base64.b64decode(source.read_text().strip()))
print(f"Wrote {target} ({target.stat().st_size} bytes)")
