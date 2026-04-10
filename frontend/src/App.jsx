import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Classify from './pages/Classify.jsx'
import Incidents from './pages/Incidents.jsx'
import AgentLog from './pages/AgentLog.jsx'

const NAV_LINKS = [
  { to: '/',          label: 'Dashboard' },
  { to: '/classify',  label: 'Classify'  },
  { to: '/incidents', label: 'Incidents' },
  { to: '/agent-log', label: 'Agent Log' },
]

export default function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Nav bar */}
      <nav className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 flex items-center gap-1 h-14">
          <span className="text-indigo-400 font-semibold text-sm mr-6 tracking-wide whitespace-nowrap">
            ⚡ Payment Reliability
          </span>
          {NAV_LINKS.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `px-4 py-1.5 text-sm rounded-md transition-colors ` +
                (isActive
                  ? 'text-indigo-300 border-b-2 border-indigo-400 bg-indigo-950/40'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60')
              }
            >
              {label}
            </NavLink>
          ))}
        </div>
      </nav>

      {/* Page content */}
      <main className="max-w-7xl mx-auto px-4 py-6">
        <Routes>
          <Route path="/"          element={<Dashboard />} />
          <Route path="/classify"  element={<Classify />}  />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/agent-log" element={<AgentLog />}  />
        </Routes>
      </main>
    </div>
  )
}
