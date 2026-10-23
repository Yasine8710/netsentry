import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import { EmptyState } from './components/ui'
import Overview from './pages/Overview'
import Traffic from './pages/Traffic'
import TrafficDetail from './pages/TrafficDetail'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="traffic" element={<Traffic />} />
          <Route path="traffic/:id" element={<TrafficDetail />} />
          <Route path="*" element={<EmptyState title="Page not found" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
