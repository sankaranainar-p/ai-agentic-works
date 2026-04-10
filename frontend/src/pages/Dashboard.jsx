import { useEffect, useState, useCallback } from 'react'
import axios from 'axios'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'

const API = import.meta.env.VITE_API_URL || ''
const API_KEY = import.meta.env.VITE_API_KEY || ''
const AUTH = API_KEY ? { 'X-API-Key': API_KEY } : {}

const SEV_COLORS = {
  'SEV-1': '#ef4444',
  'SEV-2': '#f97316',
  'SEV-3': '#eab308',
  'SEV-4': '#22c55e',
}

const PIE_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1', '#8b5cf6']

function MetricCard({ label, value, color = 'text-white' }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value ?? '—'}</p>
    </div>
  )
}

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

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [lastRefresh, setLastRefresh] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, incRes] = await Promise.all([
        axios.get(`${API}/stats`, { headers: AUTH }),
        axios.get(`${API}/incidents?limit=10`, { headers: AUTH }),
      ])
      setStats(statsRes.data)
      setIncidents(incRes.data)
      setLastRefresh(new Date())
    } catch (_) {}
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 5_000)
    return () => clearInterval(id)
  }, [fetchData])

  const catData = stats?.by_category
    ? Object.entries(stats.by_category).map(([name, count]) => ({ name, count }))
    : []

  const sevData = stats?.by_severity
    ? Object.entries(stats.by_severity).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-100">Dashboard</h1>
        {lastRefresh && (
          <span className="text-xs text-gray-500">
            Refreshed {lastRefresh.toLocaleTimeString()} · auto every 30s
          </span>
        )}
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard label="Total Incidents" value={stats?.total} />
        <MetricCard label="SEV-1" value={stats?.by_severity?.['SEV-1'] ?? 0} color="text-red-400" />
        <MetricCard label="SEV-2" value={stats?.by_severity?.['SEV-2'] ?? 0} color="text-orange-400" />
        <MetricCard label="Resolved" value={stats?.resolved ?? 0} color="text-green-400" />
      </div>

      {/* Charts */}
      {stats?.total > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Bar chart by category */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <p className="text-sm font-medium text-gray-400 mb-4">Incidents by Category</p>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={catData} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 10 }} tickLine={false} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                  labelStyle={{ color: '#e5e7eb' }}
                  itemStyle={{ color: '#818cf8' }}
                />
                <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Donut by severity */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <p className="text-sm font-medium text-gray-400 mb-4">Incidents by Severity</p>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={sevData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {sevData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name] || PIE_COLORS[0]} />
                  ))}
                </Pie>
                <Legend
                  formatter={(value) => <span style={{ color: '#9ca3af', fontSize: 12 }}>{value}</span>}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                  itemStyle={{ color: '#e5e7eb' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recent incidents table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-800">
          <p className="text-sm font-medium text-gray-400">Recent Incidents</p>
        </div>
        {incidents.length === 0 ? (
          <p className="text-gray-600 text-sm text-center py-10">No incidents yet. Use Classify to trigger one.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase border-b border-gray-800">
                <th className="px-5 py-2 text-left">ID</th>
                <th className="px-5 py-2 text-left">Category</th>
                <th className="px-5 py-2 text-left">Severity</th>
                <th className="px-5 py-2 text-left">Source</th>
                <th className="px-5 py-2 text-left">Status</th>
                <th className="px-5 py-2 text-left">Time</th>
              </tr>
            </thead>
            <tbody>
              {[...incidents].reverse().map((inc) => (
                <tr key={inc.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                  <td className="px-5 py-2.5 font-mono text-indigo-400 text-xs">{inc.id}</td>
                  <td className="px-5 py-2.5 text-gray-300">{inc.classification?.category}</td>
                  <td className="px-5 py-2.5"><SevBadge sev={inc.classification?.severity} /></td>
                  <td className="px-5 py-2.5 text-gray-500">{inc.source}</td>
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
    </div>
  )
}
