import { useEffect, useState, useCallback } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { getStats, getIncidents } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import LlmBadge from '../components/LlmBadge'

const SEV_COLORS = {
  'SEV-1': '#ef4444',
  'SEV-2': '#f97316',
  'SEV-3': '#eab308',
  'SEV-4': '#10b981',
}

function MetricCard({ label, value, color = 'text-white', sub }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value ?? '—'}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
    </div>
  )
}

const CustomBarTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="text-slate-300 font-medium mb-1">{label}</p>
      <p className="text-blue-300">{payload[0].value} incidents</p>
    </div>
  )
}

const CustomPieTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs shadow-xl">
      <p className="font-medium" style={{ color: payload[0].payload.fill }}>{payload[0].name}</p>
      <p className="text-slate-300">{payload[0].value} incidents</p>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats]       = useState(null)
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading]   = useState(true)
  const [offline, setOffline]   = useState(false)

  const load = useCallback(async () => {
    try {
      const [s, i] = await Promise.all([getStats(), getIncidents(10)])
      setStats(s.data)
      setIncidents(i.data)
      setOffline(false)
    } catch {
      setOffline(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 30_000)
    return () => clearInterval(id)
  }, [load])

  const categoriesActive = stats
    ? Object.values(stats.by_category).filter(v => v > 0).length
    : 0

  const categoryData = stats
    ? Object.entries(stats.by_category).map(([name, value]) => ({ name, value }))
    : []

  const pieData = stats
    ? Object.entries(stats.by_severity).map(([name, value]) => ({
        name,
        value,
        fill: SEV_COLORS[name] ?? '#64748b',
      }))
    : []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Incident Dashboard</h1>
          <p className="text-sm text-slate-500 mt-0.5">Live overview · auto-refreshes every 30s</p>
        </div>
      </div>

      {/* Offline banner */}
      {offline && (
        <div className="flex items-center gap-2 bg-red-900/30 border border-red-700 rounded-lg px-4 py-3 text-sm text-red-300">
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          Backend Offline — showing cached data. Check that uvicorn is running on port 8000.
        </div>
      )}

      {/* Metric cards */}
      {loading ? (
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-xl p-5 animate-pulse h-24" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            label="Total Incidents"
            value={stats?.total_incidents}
            color="text-blue-400"
            sub="in dataset"
          />
          <MetricCard
            label="SEV-1 Critical"
            value={stats?.by_severity['SEV-1']}
            color="text-red-400"
            sub="highest priority"
          />
          <MetricCard
            label="SEV-2 High"
            value={stats?.by_severity['SEV-2']}
            color="text-orange-400"
            sub="urgent attention"
          />
          <MetricCard
            label="Categories Active"
            value={categoriesActive}
            color="text-violet-400"
            sub="incident types"
          />
        </div>
      )}

      {/* Charts */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Bar chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Incidents by Category</h2>
          {loading ? (
            <div className="h-52 flex items-center justify-center">
              <span className="text-slate-500 text-sm">Loading…</span>
            </div>
          ) : categoryData.length === 0 ? (
            <div className="h-52 flex items-center justify-center">
              <span className="text-slate-500 text-sm">No data yet</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={categoryData} margin={{ top: 0, right: 0, left: -20, bottom: 60 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#64748b', fontSize: 10 }}
                  angle={-40}
                  textAnchor="end"
                  interval={0}
                />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip content={<CustomBarTooltip />} cursor={{ fill: 'rgba(99,102,241,0.08)' }} />
                <Bar dataKey="value" fill="#3b82f6" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Pie chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Distribution by Severity</h2>
          {loading ? (
            <div className="h-52 flex items-center justify-center">
              <span className="text-slate-500 text-sm">Loading…</span>
            </div>
          ) : pieData.length === 0 ? (
            <div className="h-52 flex items-center justify-center">
              <span className="text-slate-500 text-sm">No data yet</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="45%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip content={<CustomPieTooltip />} />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => <span style={{ color: '#94a3b8', fontSize: 12 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent incidents table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <h2 className="text-sm font-semibold text-slate-300">Recent Incidents</h2>
          <span className="text-xs text-slate-500">Last 10</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500 text-sm">Loading incidents…</div>
        ) : incidents.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-slate-400 text-sm">No incidents in dataset.</p>
            <p className="text-slate-600 text-xs mt-1">
              Run <code className="text-blue-400">python backend/data/generate_dataset.py</code> to seed data.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800">
                  {['Alert Text', 'Category', 'Severity', 'Source', 'Confidence', 'LLM Status', 'Override'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.id} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 text-slate-300 max-w-xs">
                      <span title={inc.title + ': ' + inc.description}>
                        {(inc.title + ': ' + inc.description).slice(0, 60)}
                        {(inc.title + inc.description).length > 60 ? '…' : ''}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs bg-blue-900/40 text-blue-300 border border-blue-800/60 px-2 py-0.5 rounded whitespace-nowrap">
                        {inc.category}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">
                      {inc.source ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">—</td>
                    <td className="px-4 py-3">
                      <LlmBadge status={inc.llm_status ?? 'unavailable'} />
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">—</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
