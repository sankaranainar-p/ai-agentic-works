import { useEffect, useState, useMemo } from 'react'
import { getIncidents } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import LlmBadge from '../components/LlmBadge'

const SEV_ORDER = { 'SEV-1': 1, 'SEV-2': 2, 'SEV-3': 3, 'SEV-4': 4 }

const ROW_BG = {
  'SEV-1': 'hover:bg-red-950/30',
  'SEV-2': 'hover:bg-orange-950/30',
  'SEV-3': 'hover:bg-yellow-950/20',
  'SEV-4': 'hover:bg-emerald-950/20',
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading]     = useState(true)
  const [offline, setOffline]     = useState(false)

  const [catFilter, setCatFilter]   = useState('')
  const [sevFilter, setSevFilter]   = useState('')
  const [llmFilter, setLlmFilter]   = useState('')
  const [sortKey, setSortKey]       = useState('severity')
  const [sortDir, setSortDir]       = useState('asc')

  useEffect(() => {
    getIncidents(50)
      .then(r => { setIncidents(r.data); setOffline(false) })
      .catch(() => setOffline(true))
      .finally(() => setLoading(false))
  }, [])

  const categories = useMemo(() => [...new Set(incidents.map(i => i.category))].sort(), [incidents])
  const severities = ['SEV-1', 'SEV-2', 'SEV-3', 'SEV-4']

  const sorted = useMemo(() => {
    let rows = [...incidents]

    if (catFilter) rows = rows.filter(r => r.category === catFilter)
    if (sevFilter) rows = rows.filter(r => r.severity === sevFilter)
    if (llmFilter === 'llm')  rows = rows.filter(r => r.llm_status === 'ok')
    if (llmFilter === 'ml')   rows = rows.filter(r => r.llm_status !== 'ok')

    rows.sort((a, b) => {
      let va, vb
      if (sortKey === 'severity') {
        va = SEV_ORDER[a.severity] ?? 9
        vb = SEV_ORDER[b.severity] ?? 9
      } else if (sortKey === 'confidence') {
        va = a.confidence ?? 0
        vb = b.confidence ?? 0
      } else {
        va = a[sortKey] ?? ''
        vb = b[sortKey] ?? ''
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1
      if (va > vb) return sortDir === 'asc' ? 1 : -1
      return 0
    })

    return rows
  }, [incidents, catFilter, sevFilter, llmFilter, sortKey, sortDir])

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  const SortIcon = ({ col }) => {
    if (sortKey !== col) return <span className="text-slate-700 ml-1">↕</span>
    return <span className="text-blue-400 ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>
  }

  const FilterSelect = ({ value, onChange, options, placeholder }) => (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500 appearance-none"
    >
      <option value="">{placeholder}</option>
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  )

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-white">Incident History</h1>
        <p className="text-sm text-slate-500 mt-0.5">Last 50 incidents from the classifier dataset</p>
      </div>

      {offline && (
        <div className="flex items-center gap-2 bg-red-900/30 border border-red-700 rounded-lg px-4 py-3 text-sm text-red-300">
          <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          Backend Offline — unable to load incidents.
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <FilterSelect
          value={catFilter}
          onChange={setCatFilter}
          placeholder="All Categories"
          options={categories.map(c => ({ value: c, label: c.replace(/_/g, ' ') }))}
        />
        <FilterSelect
          value={sevFilter}
          onChange={setSevFilter}
          placeholder="All Severities"
          options={severities.map(s => ({ value: s, label: s }))}
        />
        <FilterSelect
          value={llmFilter}
          onChange={setLlmFilter}
          placeholder="All LLM Status"
          options={[
            { value: 'llm', label: 'LLM Active' },
            { value: 'ml',  label: 'ML Fallback' },
          ]}
        />
        {(catFilter || sevFilter || llmFilter) && (
          <button
            onClick={() => { setCatFilter(''); setSevFilter(''); setLlmFilter('') }}
            className="text-xs text-slate-500 hover:text-slate-300 underline transition-colors"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-slate-500">{sorted.length} incidents</span>
      </div>

      {/* Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-slate-500 text-sm">Loading incidents…</div>
        ) : incidents.length === 0 && !offline ? (
          <div className="p-10 text-center">
            <p className="text-slate-400 text-sm">No incidents in dataset.</p>
            <p className="text-slate-600 text-xs mt-1">
              Run <code className="text-blue-400">python backend/data/generate_dataset.py</code> to seed data.
            </p>
          </div>
        ) : sorted.length === 0 ? (
          <div className="p-10 text-center text-slate-500 text-sm">No incidents match the selected filters.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/80">
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide">
                    Alert Text
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide">
                    Category
                  </th>
                  <th
                    className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-300 whitespace-nowrap select-none"
                    onClick={() => toggleSort('severity')}
                  >
                    Severity <SortIcon col="severity" />
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide">
                    Source
                  </th>
                  <th
                    className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide cursor-pointer hover:text-slate-300 whitespace-nowrap select-none"
                    onClick={() => toggleSort('confidence')}
                  >
                    Confidence <SortIcon col="confidence" />
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide">
                    LLM Status
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((inc) => (
                  <tr
                    key={inc.id}
                    className={`border-b border-slate-800/60 transition-colors ${ROW_BG[inc.severity] ?? 'hover:bg-slate-800/30'}`}
                  >
                    <td className="px-4 py-3 text-slate-300 max-w-xs">
                      <p className="font-medium text-slate-200 truncate" title={inc.title}>
                        {inc.title}
                      </p>
                      <p className="text-xs text-slate-500 truncate mt-0.5" title={inc.description}>
                        {inc.description}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs bg-blue-900/40 text-blue-300 border border-blue-800/60 px-2 py-0.5 rounded whitespace-nowrap">
                        {inc.category.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">
                      {inc.source ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">
                      {inc.confidence != null ? `${Math.round(inc.confidence * 100)}%` : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <LlmBadge status={inc.llm_status ?? 'unavailable'} />
                    </td>
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
