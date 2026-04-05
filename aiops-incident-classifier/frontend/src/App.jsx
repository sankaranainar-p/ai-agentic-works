import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Classify from './pages/Classify'
import Incidents from './pages/Incidents'

export default function App() {
  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="/"          element={<Dashboard />} />
          <Route path="/classify"  element={<Classify />} />
          <Route path="/incidents" element={<Incidents />} />
        </Routes>
      </main>
    </div>
  )
}
