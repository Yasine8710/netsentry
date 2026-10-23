import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { ProtocolStat, SeriesPoint, Severity } from '../types/api'
import { SEVERITIES } from '../types/api'
import { formatBytes, formatClock, formatNumber } from '../utils/format'
import { SEVERITY_COLOR } from './ui'

const AXIS = { fontSize: 11, fill: '#94a3b8' }
const GRID = '#22314f'
const tooltipStyle = {
  background: '#0b1220',
  border: '1px solid #22314f',
  borderRadius: 6,
  fontSize: 12,
}

export const PROTO_COLOR: Record<string, string> = {
  TCP: '#38bdf8',
  UDP: '#a78bfa',
  ICMP: '#34d399',
  OTHER: '#94a3b8',
}

export function TrafficChart({ points, bucketS }: { points: SeriesPoint[]; bucketS: number }) {
  if (points.length === 0) {
    return <p className="py-8 text-center text-sm text-slate-400">No timestamped packets to chart.</p>
  }
  const data = points.map((p) => ({ ...p, label: formatClock(p.t) }))
  return (
    <figure aria-label="Traffic volume over time">
      <div className="h-64 w-full" role="img" aria-label={`Packets per ${bucketS} second bucket over time`}>
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="pk" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="label" tick={AXIS} minTickGap={32} stroke={GRID} />
            <YAxis tick={AXIS} stroke={GRID} width={48} tickFormatter={(v: number) => formatNumber(v)} />
            <Tooltip
              contentStyle={tooltipStyle}
              labelStyle={{ color: '#cbd5e1' }}
              formatter={(v: number, name: string) => [
                name === 'bytes' ? formatBytes(v) : formatNumber(v),
                name,
              ]}
              labelFormatter={(l: string) => `${l} UTC`}
            />
            <Area
              type="monotone"
              dataKey="packets"
              stroke="#38bdf8"
              strokeWidth={1.75}
              fill="url(#pk)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="mt-1 text-xs text-slate-500">Packets per {bucketS}s bucket (UTC)</figcaption>
    </figure>
  )
}

export function ProtocolChart({ data }: { data: ProtocolStat[] }) {
  const total = data.reduce((s, d) => s + d.packets, 0)
  if (total === 0) return <p className="py-8 text-center text-sm text-slate-400">No protocol data.</p>
  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row">
      <div className="h-44 w-44 shrink-0" role="img" aria-label="Protocol distribution by packets">
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={data}
              dataKey="packets"
              nameKey="protocol"
              innerRadius={48}
              outerRadius={78}
              stroke="#0b1220"
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.protocol} fill={PROTO_COLOR[d.protocol] ?? '#64748b'} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => formatNumber(v)} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <ul className="w-full space-y-1.5 text-sm">
        {data.map((d) => (
          <li key={d.protocol} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-2 text-slate-300">
              <span
                className="h-2.5 w-2.5 rounded-sm"
                style={{ background: PROTO_COLOR[d.protocol] ?? '#64748b' }}
                aria-hidden
              />
              {d.protocol}
            </span>
            <span className="font-mono text-slate-400">
              {formatNumber(d.packets)}{' '}
              <span className="text-slate-500">({((d.packets / total) * 100).toFixed(1)}%)</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function SeverityBars({ counts }: { counts: Record<Severity, number> }) {
  const data = SEVERITIES.map((s) => ({ severity: s, count: counts[s] ?? 0 }))
  const total = data.reduce((s, d) => s + d.count, 0)
  if (total === 0) return <p className="py-6 text-center text-sm text-slate-400">No alerts detected.</p>
  return (
    <div className="h-44 w-full" role="img" aria-label="Alerts by severity">
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis type="category" dataKey="severity" tick={AXIS} width={92} stroke={GRID} />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#17233d' }} />
          <Bar
            dataKey="count"
            radius={3}
            isAnimationActive={false}
            label={{ position: 'right', fill: '#cbd5e1', fontSize: 11 }}
          >
            {data.map((d) => (
              <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
