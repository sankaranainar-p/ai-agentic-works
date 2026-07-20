import { useEffect, useState, useCallback } from 'react'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || ''
const API_KEY = import.meta.env.VITE_API_KEY || ''
const AUTH = API_KEY ? { 'X-API-Key': API_KEY } : {}

const ALL = 'all'

function SevBadge({ sev }) {
  const colors = {
    'SEV-1': 'bg-red-900/60 text-red-300',
    'SEV-2': 'bg-orange-900/60 text-orange-300',
    'SEV-3': 'bg-yellow-900/60 text-yellow-300',
    'SEV-4': 'bg-green-900/60 text-green-300',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-medium ${colors[sev] || 'bg-gray-800 text-gray-400'}`}>
      {sev}
    </span>
  )
}

function FilterPill({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`text-xs px-3 py-1 rounded-full border transition-colors ${
        active
          ? 'border-indigo-500 bg-indigo-950/50 text-indigo-300'
          : 'border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300'
      }`}
    >
      {label}
    </button>
  )
}

function DrawerSection({ title, children }) {
  return (
    <div>
      <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">{title}</p>
      {children}
    </div>
  )
}

function Drawer({ incident, onClose }) {
  if (!incident) return null
  const c = incident.classification
  const rca = incident.rca
  const rem = incident.remediation
  const ver = incident.verification

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      {/* Panel */}
      <div className="relative w-full max-w-lg bg-gray-900 border-l border-gray-700 h-full overflow-y-auto p-6 space-y-5 shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-mono text-indigo-400 text-sm">{incident.id}</p>
            <p className="text-lg font-semibold text-gray-100 mt-0.5">{c?.category}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-xl mt-0.5">✕</button>
        </div>

        <div className="flex flex-wrap gap-2">
          <SevBadge sev={c?.severity} />
          <span className={`text-xs px-2 py-0.5 rounded font-medium ${
            c?.source === 'llm' ? 'bg-violet-900/60 text-violet-300' : 'bg-blue-900/60 text-blue-300'
          }`}>
            {c?.source === 'llm' ? 'LLM' : 'ML'}
          </span>
          <span className={`text-xs px-2 py-0.5 rounded font-medium ${
            ver?.status === 'resolved' ? 'bg-green-900/60 text-green-300' : 'bg-red-900/40 text-red-400'
          }`}>
            {ver?.status}
          </span>
        </div>

        <DrawerSection title="Alert">
          <p className="text-gray-400 text-sm leading-relaxed">{incident.alert_text}</p>
        </DrawerSection>

        <DrawerSection title="Classification">
          <div className="text-sm space-y-1 text-gray-400">
            <p>Confidence: <span className="text-gray-200">{((c?.confidence ?? 0) * 100).toFixed(0)}%</span></p>
            {c?.reasoning && <p className="italic text-gray-500">"{c.reasoning}"</p>}
          </div>
        </DrawerSection>

        {rca && (
          <DrawerSection title="Root Cause Analysis">
            <div className="text-sm space-y-3 text-gray-400">
              <p className="text-gray-200">{rca.probable_cause}</p>
              {rca.contributing_factors?.length > 0 && (
                <ul className="space-y-1">
                  {rca.contributing_factors.map((f, i) => (
                    <li key={i} className="flex gap-2"><span className="text-gray-600">•</span>{f}</li>
                  ))}
                </ul>
              )}
              {rca.impact_assessment && (
                <p className="text-gray-500 text-xs">Blast radius: {rca.impact_assessment}</p>
              )}
            </div>
          </DrawerSection>
        )}

        {rem && (
          <DrawerSection title="Remediation">
            <div className="text-sm space-y-2 text-gray-400">
              <p className="text-gray-200">{rem.action_taken}</p>
              <p>{rem.details}</p>
              {rca?.immediate_actions?.length > 0 && (
                <ol className="space-y-1">
                  {rca.immediate_actions.map((a, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="text-indigo-500 font-mono text-xs">{i + 1}.</span>{a}
                    </li>
                  ))}
                </ol>
              )}
              {rem.escalated && (
                <div className="text-xs text-red-400 bg-red-950/30 border border-red-900/40 rounded px-3 py-1.5">
                  ⚠ {rem.escalation_reason}
                </div>
              )}
            </div>
          </DrawerSection>
        )}

        <DrawerSection title="Verification">
          <p className={`text-sm font-medium ${ver?.status === 'resolved' ? 'text-green-400' : 'text-red-400'}`}>
            {ver?.status === 'resolved' ? '✓ Resolved' : '✗ Unresolved'}
          </p>
          <p className="text-gray-500 text-xs mt-1">{ver?.details}</p>
        </DrawerSection>

        {incident.routing?.runbook && (
          <DrawerSection title="Runbook">
            <a
              href={incident.routing.runbook}
              className="text-indigo-400 hover:underline text-sm break-all"
            >
              {incident.routing.runbook} ↗
            </a>
          </DrawerSection>
        )}

        <p className="text-xs text-gray-600">
          {new Date(incident.started_at).toLocaleString()}
        </p>
      </div>
    </div>
  )
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [catFilter, setCatFilter] = useState(ALL)
  const [sevFilter, setSevFilter] = useState(ALL)
  const [statusFilter, setStatusFilter] = useState(ALL)
  const [selected, setSelected] = useState(null)

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await axios.get(`${API}/incidents?limit=200`, { headers: AUTH })
      setIncidents(res.data.reverse())
    } catch (_) {}
  }, [])

  useEffect(() => {
    fetchIncidents()
    const id = setInterval(fetchIncidents, 5_000)
    return () => clearInterval(id)
  }, [fetchIncidents])

  const categories = [...new Set(incidents.map((i) => i.classification?.category).filter(Boolean))]
  const severities = ['SEV-1', 'SEV-2', 'SEV-3', 'SEV-4']
  const statuses = ['resolved', 'unresolved']

  const filtered = incidents.filter((inc) => {
    if (catFilter !== ALL && inc.classification?.category !== catFilter) return false
    if (sevFilter !== ALL && inc.classification?.severity !== sevFilter) return false
    if (statusFilter !== ALL && inc.verification?.status !== statusFilter) return false
    return true
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-100">Incidents</h1>
        <button
          onClick={fetchIncidents}
          className="text-xs text-gray-500 hover:text-gray-300 border border-gray-700 rounded px-3 py-1 transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-gray-600 w-16">Category</span>
          <FilterPill label="All" active={catFilter === ALL} onClick={() => setCatFilter(ALL)} />
          {categories.map((c) => (
            <FilterPill key={c} label={c} active={catFilter === c} onClick={() => setCatFilter(c)} />
          ))}
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-gray-600 w-16">Severity</span>
          <FilterPill label="All" active={sevFilter === ALL} onClick={() => setSevFilter(ALL)} />
          {severities.map((s) => (
            <FilterPill key={s} label={s} active={sevFilter === s} onClick={() => setSevFilter(s)} />
          ))}
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-gray-600 w-16">Status</span>
          <FilterPill label="All" active={statusFilter === ALL} onClick={() => setStatusFilter(ALL)} />
          {statuses.map((s) => (
            <FilterPill key={s} label={s} active={statusFilter === s} onClick={() => setStatusFilter(s)} />
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-800 text-xs text-gray-500">
          {filtered.length} incident{filtered.length !== 1 ? 's' : ''}
        </div>
        {filtered.length === 0 ? (
          <p className="text-gray-600 text-sm text-center py-10">No incidents match the current filters.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase border-b border-gray-800">
                <th className="px-5 py-2 text-left">ID</th>
                <th className="px-5 py-2 text-left">Category</th>
                <th className="px-5 py-2 text-left">Severity</th>
                <th className="px-5 py-2 text-left">Confidence</th>
                <th className="px-5 py-2 text-left">Status</th>
                <th className="px-5 py-2 text-left">Time</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((inc) => (
                <tr
                  key={inc.id}
                  onClick={() => setSelected(inc)}
                  className="border-b border-gray-800/50 hover:bg-gray-800/40 cursor-pointer transition-colors"
                >
                  <td className="px-5 py-2.5 font-mono text-indigo-400 text-xs">{inc.id}</td>
                  <td className="px-5 py-2.5 text-gray-300">{inc.classification?.category}</td>
                  <td className="px-5 py-2.5"><SevBadge sev={inc.classification?.severity} /></td>
                  <td className="px-5 py-2.5 text-gray-400">
                    {((inc.classification?.confidence ?? 0) * 100).toFixed(0)}%
                  </td>
                  <td className="px-5 py-2.5">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                      inc.verification?.status === 'resolved'
                        ? 'bg-green-900/60 text-green-300'
                        : 'bg-red-900/40 text-red-400'
                    }`}>
                      {inc.verification?.status ?? 'unknown'}
                    </span>
                  </td>
                  <td className="px-5 py-2.5 text-gray-600 text-xs">
                    {new Date(inc.started_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Drawer incident={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
