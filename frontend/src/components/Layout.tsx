import { Activity, FileText, LayoutDashboard, Menu, Settings, ShieldAlert, X } from 'lucide-react'
import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/traffic', label: 'Traffic analysis', icon: Activity, end: false },
  { to: '/alerts', label: 'Threat detection', icon: ShieldAlert, end: false },
  { to: '/reports', label: 'Reports', icon: FileText, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
]

export default function Layout() {
  const [open, setOpen] = useState(false)
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[232px_1fr]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-cyan-500 focus:px-3 focus:py-1 focus:text-ink-950"
      >
        Skip to content
      </a>
      <header className="flex items-center justify-between border-b border-ink-600/60 bg-ink-900 px-4 py-3 lg:hidden">
        <Brand />
        <button
          type="button"
          aria-label={open ? 'Close menu' : 'Open menu'}
          aria-expanded={open}
          aria-controls="sidebar"
          onClick={() => setOpen((o) => !o)}
          className="rounded p-1.5 text-slate-300 hover:bg-ink-700"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </header>
      <aside
        id="sidebar"
        className={`${open ? 'block' : 'hidden'} border-r border-ink-600/60 bg-ink-900 lg:sticky lg:top-0 lg:block lg:h-screen`}
      >
        <div className="hidden px-5 py-5 lg:block">
          <Brand />
        </div>
        <nav aria-label="Main" className="flex flex-col gap-1 px-3 pb-4 lg:pt-0">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300'
                    : 'text-slate-400 hover:bg-ink-700/70 hover:text-slate-100'
                }`
              }
            >
              <Icon className="h-4 w-4" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        <p className="hidden px-5 pt-4 text-[11px] leading-snug text-slate-500 lg:block">
          Defensive analysis only. Detections are heuristics, not proof of an attack.
        </p>
      </aside>
      <main id="main" className="min-w-0 px-4 py-6 sm:px-8">
        <div className="mx-auto max-w-6xl">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

function Brand() {
  return (
    <div className="flex items-center gap-2">
      <ShieldAlert className="h-5 w-5 text-cyan-400" aria-hidden />
      <span className="text-base font-semibold tracking-tight text-slate-50">NetSentry</span>
    </div>
  )
}
