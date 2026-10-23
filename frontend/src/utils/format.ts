export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '-'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`
}

export const formatNumber = (n: number | null | undefined): string =>
  n === null || n === undefined ? '-' : n.toLocaleString('en-US')

export function formatDuration(s: number | null | undefined): string {
  if (s === null || s === undefined) return '-'
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`
  if (s < 60) return `${s.toFixed(1)} s`
  const m = Math.floor(s / 60)
  const sec = Math.round(s % 60)
  if (m < 60) return `${m}m ${sec}s`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

/** Epoch seconds -> "2024-01-31 12:00:00 UTC". */
export function formatTs(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || !Number.isFinite(ts)) return '-'
  const d = new Date(ts * 1000)
  if (Number.isNaN(d.getTime())) return '-'
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
}

export function formatClock(ts: number): string {
  const d = new Date(ts * 1000)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(11, 19)
}

export function formatIso(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
}

export const humanize = (s: string): string => s.replace(/_/g, ' ')

const FLAGS: [number, string][] = [
  [0x02, 'SYN'],
  [0x10, 'ACK'],
  [0x01, 'FIN'],
  [0x04, 'RST'],
  [0x08, 'PSH'],
  [0x20, 'URG'],
]
export const tcpFlagNames = (f: number | null): string =>
  f === null
    ? ''
    : FLAGS.filter(([b]) => f & b)
        .map(([, n]) => n)
        .join(',') || 'none'
