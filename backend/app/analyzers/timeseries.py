"""Fixed-memory traffic time series with automatic bucket coarsening."""


class TimeSeries:
    """Packets/bytes per time bucket. Bucket width doubles when the bucket cap is exceeded."""

    def __init__(self, bucket_s: float = 1.0, max_buckets: int = 5000) -> None:
        self.bucket_s = bucket_s
        self.max_buckets = max_buckets
        self._b: dict[int, list[int]] = {}

    def add(self, ts: float, nbytes: int) -> None:
        idx = int(ts // self.bucket_s)
        cell = self._b.get(idx)
        if cell is None:
            self._b[idx] = [1, nbytes]
        else:
            cell[0] += 1
            cell[1] += nbytes
        if len(self._b) > self.max_buckets:
            self._coarsen()

    def _coarsen(self) -> None:
        self.bucket_s *= 2
        merged: dict[int, list[int]] = {}
        for idx, (p, b) in self._b.items():
            # old bucket idx covered [idx*w, (idx+1)*w); new width is 2w
            ni = idx // 2
            cell = merged.setdefault(ni, [0, 0])
            cell[0] += p
            cell[1] += b
        self._b = merged

    def points(self) -> list[dict]:
        """Non-empty buckets in time order, with zero-filled gaps omitted."""
        return [
            {"t": idx * self.bucket_s, "packets": p, "bytes": b}
            for idx, (p, b) in sorted(self._b.items())
        ]

    def dense_packet_counts(self) -> list[int]:
        """Packet counts per bucket including empty buckets (for baseline statistics)."""
        if not self._b:
            return []
        lo, hi = min(self._b), max(self._b)
        return [self._b.get(i, [0, 0])[0] for i in range(lo, hi + 1)]
