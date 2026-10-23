import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import { EmptyState } from './components/ui'
import { api } from './services/api'
import Alerts from './pages/Alerts'
import Overview from './pages/Overview'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import Traffic from './pages/Traffic'
import TrafficDetail from './pages/TrafficDetail'
import type { AppSettings } from './types/api'

function applyUi(ui: AppSettings['ui']) {
  document.documentElement.dataset.density = ui.density
  document.documentElement.dataset.reducedMotion = String(ui.reduced_motion)
}

export default function App() {
  useEffect(() => {
    api
      .getSettings()
      .then((s) => applyUi(s.ui))
      .catch(() => undefined)
  }, [])
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="traffic" element={<Traffic />} />
          <Route path="traffic/:id" element={<TrafficDetail />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="alerts/:id" element={<Alerts />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings onSaved={(s) => applyUi(s.ui)} />} />
          <Route path="*" element={<EmptyState title="Page not found" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
