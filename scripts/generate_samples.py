"""Generate synthetic sample captures into data/samples/ (local files only, no network I/O)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.analyzers.synthetic import (  # noqa: E402
    demo_capture,
    normal_traffic,
    port_scan,
    write_pcap,
)


def main() -> None:
    out = ROOT / "data" / "samples"
    out.mkdir(parents=True, exist_ok=True)
    write_pcap(out / "normal.pcap", normal_traffic(n=120))
    write_pcap(
        out / "port_scan.pcap",
        port_scan("203.0.113.66", "10.0.0.10", range(1, 61)) + normal_traffic(1000.0, n=40),
    )
    write_pcap(out / "demo_mixed.pcap", demo_capture())
    for f in sorted(out.glob("*.pcap")):
        print(f"{f.name}: {f.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
